//! Simple TUI Snake for the HuesOS terminal.
//!
//! Classic: `snake` — normal pace, no hazards.
//! Hard:    `snake hard` — every 2 apples a random event:
//!   1) Bombs (small / large blast radius)
//!   2) AK short burst across a row/col
//!   3) Homing rocket that chases the head for ~3s
//!
//! Controls: WASD/HJKL, Enter restart, Esc quit to shell.

use libcanvas::framebuffer::Canvas;
use libcanvas::{Channel, ErrorCode};

const GRID_W: usize = 32;
const GRID_H: usize = 18;
const MAX_LEN: usize = GRID_W * GRID_H;
const HUD_HEIGHT: u32 = 58;
const EDGE_PAD: u32 = 8;

#[derive(Clone, Copy)]
struct Layout {
    cell: u32,
    board_x: u32,
    board_y: u32,
    board_w: u32,
    board_h: u32,
}

impl Layout {
    fn fullscreen(canvas: &Canvas) -> Self {
        let available_w = canvas.width().saturating_sub(EDGE_PAD * 2);
        let available_h = canvas
            .height()
            .saturating_sub(HUD_HEIGHT + EDGE_PAD);
        let cell = (available_w / GRID_W as u32)
            .min(available_h / GRID_H as u32)
            .max(1);
        let board_w = cell * GRID_W as u32;
        let board_h = cell * GRID_H as u32;
        Self {
            cell,
            board_x: canvas.width().saturating_sub(board_w) / 2,
            board_y: HUD_HEIGHT,
            board_w,
            board_h,
        }
    }
}

// Snake pace is expressed only in kernel monotonic 100 Hz ticks. Never use
// RDTSC here: TSC frequency, virtualization and power management differ across
// devices and made identical builds run at different speeds.
const BASE_STEP_TICKS: u64 = 10;
const MIN_STEP_TICKS: u64 = 6;

// Hard-mode event limits and lifetimes, all expressed in snake steps.
const MAX_BOMBS: usize = 6;
const MAX_BULLETS: usize = 16;
const ROCKET_LIFE_STEPS: u32 = 30;
const BOMB_FUSE_SMALL: u32 = 12;
const BOMB_FUSE_LARGE: u32 = 16;
const BOMB_R_SMALL: i16 = 1;
const BOMB_R_LARGE: i16 = 2;
const AK_BURST: usize = 5;

fn step_delay_ticks(score: u32) -> u64 {
    // Mild speed-up: every 5 food, -1 tick/10 ms, never below MIN_STEP_TICKS.
    let faster_ticks = score as u64 / 5;
    BASE_STEP_TICKS
        .saturating_sub(faster_ticks)
        .max(MIN_STEP_TICKS)
}

/// Wait one snake step against the kernel monotonic clock. Keyboard events
/// may wake the channel early, but they never advance the game clock.
fn wait_step(
    score: u32,
    keyboard: &Channel,
    dir: Dir,
    pending: &mut Dir,
    phase: Phase,
) -> Option<Action> {
    let step_ticks = step_delay_ticks(score);
    let start = libcanvas::system::monotonic_ticks().unwrap_or(0);
    let deadline = start.saturating_add(step_ticks);
    let mut fallback_elapsed = 0u64;
    let mut buf = [0u8; 16];

    loop {
        loop {
            match keyboard.read_into(&mut buf) {
                Ok(n) if n > 0 => {
                    if let Some(result) = apply_input(&buf[..n], dir, pending, phase) {
                        return Some(result);
                    }
                }
                _ => break,
            }
        }

        match libcanvas::system::monotonic_ticks() {
            Ok(now) if now >= deadline => return None,
            Ok(_) => {}
            Err(_) if fallback_elapsed >= step_ticks => return None,
            Err(_) => {}
        }

        match keyboard.read_into_timeout(&mut buf, 1) {
            Ok(n) if n > 0 => {
                if let Some(result) = apply_input(&buf[..n], dir, pending, phase) {
                    return Some(result);
                }
            }
            Err(ErrorCode::TimedOut) => fallback_elapsed = fallback_elapsed.saturating_add(1),
            _ => {}
        }
    }
}

fn apply_input(msg: &[u8], dir: Dir, pending: &mut Dir, phase: Phase) -> Option<Action> {
    let action = decode(msg)?;
    match phase {
        Phase::Playing => match action {
            Action::Dir(next) => {
                if !is_opposite(dir, next) && !is_opposite(*pending, next) {
                    *pending = next;
                }
                None
            }
            Action::Esc => Some(Action::Esc),
            Action::Enter => None,
        },
        Phase::GameOver => match action {
            Action::Enter | Action::Esc => Some(action),
            Action::Dir(_) => None,
        },
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Dir {
    Up,
    Down,
    Left,
    Right,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Playing,
    GameOver,
}

#[derive(Clone, Copy)]
struct Point {
    x: u8,
    y: u8,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum BombKind {
    Small,
    Large,
}

#[derive(Clone, Copy)]
struct Bomb {
    pos: Point,
    fuse: u32,
    kind: BombKind,
    alive: bool,
}

#[derive(Clone, Copy)]
struct Bullet {
    pos: Point,
    dir: Dir,
    alive: bool,
    /// Accumulated slowdown: the bullet skips this many upcoming steps.
    /// Grows by 1 every time the bullet punches through a regular apple.
    slow: u8,
}

#[derive(Clone, Copy)]
struct Rocket {
    pos: Point,
    life: u32,
    alive: bool,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum EventBanner {
    None,
    Bombs,
    Ak,
    Rocket,
}

#[derive(Clone, Copy)]
struct GoldFood {
    pos: Point,
    ttl: u32,
}

/// Run Snake. `hard` enables random hazard events every 2 apples.
pub fn run(keyboard: &Channel, hard: bool) {
    let Ok(canvas) = Canvas::new_fullscreen() else {
        return;
    };

    let layout = Layout::fullscreen(&canvas);

    let mut body = [Point { x: 0, y: 0 }; MAX_LEN];
    let mut len = 0usize;
    let mut dir = Dir::Right;
    let mut pending = Dir::Right;
    let mut food = Point { x: 10, y: 8 };
    let mut gold_food: Option<GoldFood> = None;
    let mut phase = Phase::Playing;
    let mut score = 0u32;
    let mut rng = 0xC0FF_EE42u32;

    let mut bombs = [Bomb {
        pos: Point { x: 0, y: 0 },
        fuse: 0,
        kind: BombKind::Small,
        alive: false,
    }; MAX_BOMBS];
    let mut bullets = [Bullet {
        pos: Point { x: 0, y: 0 },
        dir: Dir::Right,
        alive: false,
        slow: 0,
    }; MAX_BULLETS];
    let mut rocket = Rocket {
        pos: Point { x: 0, y: 0 },
        life: 0,
        alive: false,
    };
    let mut banner = EventBanner::None;
    let mut banner_ttl: u32 = 0;
    // Pending event to fire right after eating (when score hits 2,4,6…).
    let mut pending_event = false;

    reset(
        &mut body,
        &mut len,
        &mut dir,
        &mut pending,
        &mut food,
        &mut gold_food,
        &mut score,
        &mut phase,
        &mut rng,
        &mut bombs,
        &mut bullets,
        &mut rocket,
        &mut banner,
        &mut banner_ttl,
        &mut pending_event,
    );
    draw(
        &canvas, &layout, hard, &body, len, food, gold_food, phase, score, &bombs, &bullets,
        &rocket, banner,
    );

    loop {
        // Wait one paced step, polling keys the whole time via blocking timeouts.
        if let Some(action) = wait_step(score, keyboard, dir, &mut pending, phase) {
            match phase {
                Phase::Playing => {
                    // Only Esc is returned from wait_step in Playing.
                    if matches!(action, Action::Esc) {
                        return;
                    }
                }
                Phase::GameOver => match action {
                    Action::Enter => {
                        reset(
                            &mut body,
                            &mut len,
                            &mut dir,
                            &mut pending,
                            &mut food,
                            &mut gold_food,
                            &mut score,
                            &mut phase,
                            &mut rng,
                            &mut bombs,
                            &mut bullets,
                            &mut rocket,
                            &mut banner,
                            &mut banner_ttl,
                            &mut pending_event,
                        );
                        draw(
                            &canvas, &layout, hard, &body, len, food, gold_food, phase, score,
                            &bombs, &bullets, &rocket, banner,
                        );
                        continue;
                    }
                    Action::Esc => return,
                    Action::Dir(_) => {}
                },
            }
        }

        if phase != Phase::Playing {
            // Game over: keep polling via wait_step.
            continue;
        }

        dir = pending;

        // 1) Move snake
        if !step(
            &mut body,
            &mut len,
            dir,
            &mut food,
            &mut gold_food,
            &mut score,
            &mut rng,
            hard,
            &mut pending_event,
            &bombs,
            &bullets,
            &rocket,
        ) {
            phase = Phase::GameOver;
        }

        // 2) Spawn hard-mode event after every 2 apples
        if hard && pending_event && phase == Phase::Playing {
            pending_event = false;
            spawn_event(
                &mut rng,
                &body,
                len,
                &mut bombs,
                &mut bullets,
                &mut rocket,
                &mut banner,
                &mut banner_ttl,
            );
        }

        // 3) Tick hazards
        if hard && phase == Phase::Playing {
            if !tick_hazards(
                &mut bombs,
                &mut bullets,
                &mut rocket,
                &body,
                len,
                &mut rng,
                &mut food,
                &mut gold_food,
            ) {
                phase = Phase::GameOver;
            }
        }

        if banner_ttl > 0 {
            banner_ttl -= 1;
            if banner_ttl == 0 {
                banner = EventBanner::None;
            }
        }

        draw(
            &canvas, &layout, hard, &body, len, food, gold_food, phase, score, &bombs, &bullets,
            &rocket, banner,
        );
    }
}

fn reset(
    body: &mut [Point; MAX_LEN],
    len: &mut usize,
    dir: &mut Dir,
    pending: &mut Dir,
    food: &mut Point,
    gold_food: &mut Option<GoldFood>,
    score: &mut u32,
    phase: &mut Phase,
    rng: &mut u32,
    bombs: &mut [Bomb; MAX_BOMBS],
    bullets: &mut [Bullet; MAX_BULLETS],
    rocket: &mut Rocket,
    banner: &mut EventBanner,
    banner_ttl: &mut u32,
    pending_event: &mut bool,
) {
    body[0] = Point { x: 8, y: 8 };
    body[1] = Point { x: 7, y: 8 };
    body[2] = Point { x: 6, y: 8 };
    *len = 3;
    *dir = Dir::Right;
    *pending = Dir::Right;
    *score = 0;
    *phase = Phase::Playing;
    *gold_food = None;
    *food = spawn_food(body, *len, rng, bombs, bullets, rocket, *gold_food, None);
    for b in bombs.iter_mut() {
        b.alive = false;
    }
    for b in bullets.iter_mut() {
        b.alive = false;
    }
    rocket.alive = false;
    *banner = EventBanner::None;
    *banner_ttl = 0;
    *pending_event = false;
}

fn step(
    body: &mut [Point; MAX_LEN],
    len: &mut usize,
    dir: Dir,
    food: &mut Point,
    gold_food: &mut Option<GoldFood>,
    score: &mut u32,
    rng: &mut u32,
    hard: bool,
    pending_event: &mut bool,
    bombs: &[Bomb; MAX_BOMBS],
    bullets: &[Bullet; MAX_BULLETS],
    rocket: &Rocket,
) -> bool {
    let head = body[0];
    let mut nx = head.x as i16;
    let mut ny = head.y as i16;
    match dir {
        Dir::Up => ny -= 1,
        Dir::Down => ny += 1,
        Dir::Left => nx -= 1,
        Dir::Right => nx += 1,
    }
    if nx < 0 || ny < 0 || nx as usize >= GRID_W || ny as usize >= GRID_H {
        return false;
    }
    let next = Point {
        x: nx as u8,
        y: ny as u8,
    };
    for i in 0..*len {
        if body[i].x == next.x && body[i].y == next.y {
            return false;
        }
    }

    let eat = next.x == food.x && next.y == food.y;

    let mut eat_gold = false;
    if let Some(gf) = gold_food {
        if next.x == gf.pos.x && next.y == gf.pos.y {
            eat_gold = true;
        }
    }

    if eat {
        if *len + 1 < MAX_LEN {
            *len += 1;
        }
        *score = score.saturating_add(1);
        if hard && *score % 2 == 0 {
            *pending_event = true;
        }
    } else if eat_gold {
        *score = score.saturating_add(3);
        *gold_food = None;
        if hard {
            *pending_event = true;
        }
    }

    // Guard against a zero-length body: `*len - 1` would underflow.
    // Today `reset()` seeds len=3 and it only grows, but this keeps
    // `step()` safe if a future caller ever runs it with an empty body.
    if *len > 0 {
        let mut i = *len - 1;
        while i > 0 {
            body[i] = body[i - 1];
            i -= 1;
        }
        body[0] = next;
    } else {
        body[0] = next;
        *len = 1;
    }

    if eat {
        *food = spawn_food(body, *len, rng, bombs, bullets, rocket, *gold_food, None);

        // 20% chance to spawn a Golden Apple (Gold Food)
        *rng = rng.wrapping_mul(1664525).wrapping_add(1013904223);
        if gold_food.is_none() && (*rng % 5 == 0) {
            // Pass the freshly respawned regular apple as `avoid` so the gold
            // apple can never overlap it. Previously we relied on a
            // `(+3, +3) % GRID` fallback that could land on the snake, a
            // bomb, or a bullet.
            let gp = spawn_food(body, *len, rng, bombs, bullets, rocket, None, Some(*food));
            *gold_food = Some(GoldFood {
                pos: gp,
                ttl: 30, // 30 steps active
            });
        }
    }

    // Tick golden apple TTL
    if let Some(gf) = gold_food {
        let mut updated_gf = *gf;
        if updated_gf.ttl > 0 {
            updated_gf.ttl -= 1;
            if updated_gf.ttl == 0 {
                *gold_food = None;
            } else {
                *gold_food = Some(updated_gf);
            }
        }
    }

    true
}

fn spawn_food(
    body: &[Point; MAX_LEN],
    len: usize,
    rng: &mut u32,
    bombs: &[Bomb; MAX_BOMBS],
    bullets: &[Bullet; MAX_BULLETS],
    rocket: &Rocket,
    gold_food: Option<GoldFood>,
    // Extra cell to avoid — used when spawning a gold apple to keep it off
    // the freshly respawned regular apple.
    avoid: Option<Point>,
) -> Point {
    for _ in 0..512 {
        *rng = rng.wrapping_mul(1664525).wrapping_add(1013904223);
        let x = (*rng as usize % GRID_W) as u8;
        let y = ((*rng >> 16) as usize % GRID_H) as u8;

        let mut free = true;
        for i in 0..len {
            if body[i].x == x && body[i].y == y {
                free = false;
                break;
            }
        }
        if free {
            for b in bombs.iter() {
                if b.alive && b.pos.x == x && b.pos.y == y {
                    free = false;
                    break;
                }
            }
        }
        if free {
            for b in bullets.iter() {
                if b.alive && b.pos.x == x && b.pos.y == y {
                    free = false;
                    break;
                }
            }
        }
        if free && rocket.alive && rocket.pos.x == x && rocket.pos.y == y {
            free = false;
        }
        if free {
            if let Some(gf) = gold_food {
                if gf.pos.x == x && gf.pos.y == y {
                    free = false;
                }
            }
        }
        if free {
            if let Some(a) = avoid {
                if a.x == x && a.y == y {
                    free = false;
                }
            }
        }

        if free {
            return Point { x, y };
        }
    }
    Point { x: 1, y: 1 }
}

fn is_opposite(a: Dir, b: Dir) -> bool {
    matches!(
        (a, b),
        (Dir::Up, Dir::Down)
            | (Dir::Down, Dir::Up)
            | (Dir::Left, Dir::Right)
            | (Dir::Right, Dir::Left)
    )
}

fn on_snake(body: &[Point; MAX_LEN], len: usize, p: Point) -> bool {
    for i in 0..len {
        if body[i].x == p.x && body[i].y == p.y {
            return true;
        }
    }
    false
}

fn spawn_event(
    rng: &mut u32,
    body: &[Point; MAX_LEN],
    len: usize,
    bombs: &mut [Bomb; MAX_BOMBS],
    bullets: &mut [Bullet; MAX_BULLETS],
    rocket: &mut Rocket,
    banner: &mut EventBanner,
    banner_ttl: &mut u32,
) {
    *rng = rng.wrapping_mul(1103515245).wrapping_add(12345);
    let kind = *rng % 3;
    match kind {
        0 => {
            // Bombs: 1–2 small and maybe 1 large
            *banner = EventBanner::Bombs;
            *banner_ttl = 18;
            let n_small = 1 + (*rng >> 8) as usize % 2;
            for _ in 0..n_small {
                place_bomb(rng, body, len, bombs, BombKind::Small);
            }
            if (*rng >> 16) & 1 == 1 {
                place_bomb(rng, body, len, bombs, BombKind::Large);
            }
        }
        1 => {
            // AK burst from a board edge toward the head row/col
            *banner = EventBanner::Ak;
            *banner_ttl = 14;
            fire_ak(rng, body, bullets);
        }
        _ => {
            // Homing rocket near opposite side of head
            *banner = EventBanner::Rocket;
            *banner_ttl = 18;
            let head = body[0];
            rocket.pos = Point {
                x: if head.x < (GRID_W as u8 / 2) {
                    (GRID_W as u8).saturating_sub(2)
                } else {
                    1
                },
                y: if head.y < (GRID_H as u8 / 2) {
                    (GRID_H as u8).saturating_sub(2)
                } else {
                    1
                },
            };
            rocket.life = ROCKET_LIFE_STEPS;
            rocket.alive = true;
        }
    }
}

fn place_bomb(
    rng: &mut u32,
    body: &[Point; MAX_LEN],
    len: usize,
    bombs: &mut [Bomb; MAX_BOMBS],
    kind: BombKind,
) {
    let slot = bombs.iter_mut().find(|b| !b.alive);
    let Some(slot) = slot else {
        return;
    };
    for _ in 0..64 {
        *rng = rng.wrapping_mul(1664525).wrapping_add(1013904223);
        let p = Point {
            x: (*rng as usize % GRID_W) as u8,
            y: ((*rng >> 16) as usize % GRID_H) as u8,
        };
        // Prefer not on head
        if body[0].x == p.x && body[0].y == p.y {
            continue;
        }
        let _ = len;
        slot.pos = p;
        slot.kind = kind;
        slot.fuse = match kind {
            BombKind::Small => BOMB_FUSE_SMALL,
            BombKind::Large => BOMB_FUSE_LARGE,
        };
        slot.alive = true;
        return;
    }
}

fn fire_ak(rng: &mut u32, body: &[Point; MAX_LEN], bullets: &mut [Bullet; MAX_BULLETS]) {
    let head = body[0];
    *rng = rng.wrapping_mul(22695477).wrapping_add(1);
    // Prefer horizontal or vertical sweep through the head.
    let horizontal = (*rng & 1) == 0;
    let (start, dir) = if horizontal {
        if head.x < GRID_W as u8 / 2 {
            (Point { x: 0, y: head.y }, Dir::Right)
        } else {
            (
                Point {
                    x: (GRID_W as u8).saturating_sub(1),
                    y: head.y,
                },
                Dir::Left,
            )
        }
    } else if head.y < GRID_H as u8 / 2 {
        (Point { x: head.x, y: 0 }, Dir::Down)
    } else {
        (
            Point {
                x: head.x,
                y: (GRID_H as u8).saturating_sub(1),
            },
            Dir::Up,
        )
    };

    let mut placed = 0usize;
    for b in bullets.iter_mut() {
        if placed >= AK_BURST {
            break;
        }
        if b.alive {
            continue;
        }
        // Stagger burst along the axis behind the muzzle.
        let mut p = start;
        for _ in 0..placed {
            p = step_point(p, opposite(dir)).unwrap_or(p);
        }
        b.pos = p;
        b.dir = dir;
        b.alive = true;
        b.slow = 0;
        placed += 1;
    }
}

fn opposite(d: Dir) -> Dir {
    match d {
        Dir::Up => Dir::Down,
        Dir::Down => Dir::Up,
        Dir::Left => Dir::Right,
        Dir::Right => Dir::Left,
    }
}

fn step_point(p: Point, d: Dir) -> Option<Point> {
    let mut x = p.x as i16;
    let mut y = p.y as i16;
    match d {
        Dir::Up => y -= 1,
        Dir::Down => y += 1,
        Dir::Left => x -= 1,
        Dir::Right => x += 1,
    }
    if x < 0 || y < 0 || x as usize >= GRID_W || y as usize >= GRID_H {
        None
    } else {
        Some(Point {
            x: x as u8,
            y: y as u8,
        })
    }
}

/// Tick bombs/bullets/rocket. Returns false if snake dies.
fn tick_hazards(
    bombs: &mut [Bomb; MAX_BOMBS],
    bullets: &mut [Bullet; MAX_BULLETS],
    rocket: &mut Rocket,
    body: &[Point; MAX_LEN],
    len: usize,
    rng: &mut u32,
    food: &mut Point,
    gold_food: &mut Option<GoldFood>,
) -> bool {
    // Bombs: countdown and explode
    for b in bombs.iter_mut() {
        if !b.alive {
            continue;
        }
        if b.fuse > 0 {
            b.fuse -= 1;
        }
        if b.fuse == 0 {
            let r = match b.kind {
                BombKind::Small => BOMB_R_SMALL,
                BombKind::Large => BOMB_R_LARGE,
            };
            if blast_hits_snake(b.pos, r, body, len) {
                b.alive = false;
                return false;
            }
            b.alive = false;
        }
    }

    // Bullets fly one cell per step, unless they are cooling down after
    // punching through an apple. Each pierced apple adds +1 tick of skip
    // to the cumulative `slow` counter, so a bullet that eats many apples
    // eventually grinds to a near-halt (but never dies from cooldown alone).
    //
    // Interaction rules (see PR notes):
    //   * Regular apple  -> bullet keeps flying, apple respawns,   slow += 1
    //   * Gold apple     -> bullet dies, gold apple survives (armor)
    //   * Snake body     -> bullet dies, snake dies (game over)
    //   * Board edge     -> bullet dies
    //
    // We iterate by index because respawning a pierced apple needs to call
    // spawn_food(..., bullets, ...) which conflicts with an iter_mut()
    // borrow on the bullets slice. A snapshot copy lets us pass the bullet
    // positions into spawn_food while still mutating `bullets` here.
    for i in 0..bullets.len() {
        if !bullets[i].alive {
            continue;
        }
        // Snake standing where the bullet already is? That still kills.
        if on_snake(body, len, bullets[i].pos) {
            bullets[i].alive = false;
            return false;
        }
        // Cooldown: skip this step's movement but keep the bullet alive.
        if bullets[i].slow > 0 {
            bullets[i].slow -= 1;
            continue;
        }
        match step_point(bullets[i].pos, bullets[i].dir) {
            Some(np) => {
                bullets[i].pos = np;
                if on_snake(body, len, bullets[i].pos) {
                    bullets[i].alive = false;
                    return false;
                }
                // Gold apple acts as armor: bullet dies, apple survives.
                if let Some(gf) = *gold_food {
                    if gf.pos.x == bullets[i].pos.x && gf.pos.y == bullets[i].pos.y {
                        bullets[i].alive = false;
                        continue;
                    }
                }
                // Regular apple: pierce through, respawn it, accumulate slow.
                if food.x == bullets[i].pos.x && food.y == bullets[i].pos.y {
                    let bullets_snapshot = *bullets;
                    *food = spawn_food(
                        body,
                        len,
                        rng,
                        bombs,
                        &bullets_snapshot,
                        rocket,
                        *gold_food,
                        None,
                    );
                    bullets[i].slow = bullets[i].slow.saturating_add(1);
                }
            }
            None => bullets[i].alive = false,
        }
    }

    // Homing rocket: chase head for ROCKET_LIFE_STEPS
    if rocket.alive {
        if on_snake(body, len, rocket.pos) {
            rocket.alive = false;
            return false;
        }
        if rocket.life == 0 {
            rocket.alive = false;
        } else {
            rocket.life -= 1;
            let head = body[0];
            // Step one cell toward head (Manhattan greedy, random on tie).
            let dx = head.x as i16 - rocket.pos.x as i16;
            let dy = head.y as i16 - rocket.pos.y as i16;
            *rng = rng.wrapping_mul(1103515245).wrapping_add(12345);
            let prefer_x = if dx.abs() == dy.abs() {
                (*rng & 1) == 0
            } else {
                dx.abs() > dy.abs()
            };
            let dir = if prefer_x {
                if dx > 0 {
                    Dir::Right
                } else if dx < 0 {
                    Dir::Left
                } else if dy > 0 {
                    Dir::Down
                } else {
                    Dir::Up
                }
            } else if dy > 0 {
                Dir::Down
            } else if dy < 0 {
                Dir::Up
            } else if dx > 0 {
                Dir::Right
            } else {
                Dir::Left
            };
            if let Some(np) = step_point(rocket.pos, dir) {
                rocket.pos = np;
            }
            if on_snake(body, len, rocket.pos) {
                rocket.alive = false;
                return false;
            }
            if rocket.life == 0 {
                rocket.alive = false;
            }
        }
    }

    true
}

fn blast_hits_snake(center: Point, radius: i16, body: &[Point; MAX_LEN], len: usize) -> bool {
    for i in 0..len {
        let dx = body[i].x as i16 - center.x as i16;
        let dy = body[i].y as i16 - center.y as i16;
        if dx.abs() <= radius && dy.abs() <= radius {
            return true;
        }
    }
    false
}

enum Action {
    Dir(Dir),
    Enter,
    Esc,
}

fn decode(msg: &[u8]) -> Option<Action> {
    match msg {
        [b'c', b] => match *b {
            b'w' | b'W' | b'k' | b'K' => Some(Action::Dir(Dir::Up)),
            b's' | b'S' | b'j' | b'J' => Some(Action::Dir(Dir::Down)),
            b'a' | b'A' | b'h' | b'H' => Some(Action::Dir(Dir::Left)),
            b'd' | b'D' | b'l' | b'L' => Some(Action::Dir(Dir::Right)),
            27 => Some(Action::Esc),
            _ => None,
        },
        b"enter" => Some(Action::Enter),
        b"backspace" => None,
        _ => None,
    }
}

fn draw(
    canvas: &Canvas,
    layout: &Layout,
    hard: bool,
    body: &[Point; MAX_LEN],
    len: usize,
    food: Point,
    gold_food: Option<GoldFood>,
    phase: Phase,
    score: u32,
    bombs: &[Bomb; MAX_BOMBS],
    bullets: &[Bullet; MAX_BULLETS],
    rocket: &Rocket,
    banner: EventBanner,
) {
    // Layered full-screen background and HUD panel.
    let _ = canvas.fill_rect(0, 0, canvas.width(), canvas.height(), 4, 8, 16);
    let _ = canvas.fill_rect(0, 0, canvas.width(), HUD_HEIGHT, 10, 24, 40);
    let _ = canvas.fill_rect(0, HUD_HEIGHT - 2, canvas.width(), 2, 40, 150, 180);

    let title = if hard {
        "HuesOS Snake  [HARD]"
    } else {
        "HuesOS Snake"
    };
    let _ = canvas.draw_text(layout.board_x, 12, title, 200, 230, 255);
    let mut score_buf = [0u8; 24];
    let score_txt = format_labeled_u32(&mut score_buf, "Score: ", score);
    let _ = canvas.draw_text(layout.board_x + 220, 12, score_txt, 180, 220, 160);

    let help = if hard {
        "WASD move | Esc quit | every 2 apples: random hazard"
    } else {
        "WASD/HJKL move | Esc quit | try: snake hard"
    };
    let _ = canvas.draw_text(layout.board_x, 28, help, 140, 160, 180);

    // Event banner
    let banner_txt = match banner {
        EventBanner::None => "",
        EventBanner::Bombs => "!! BOMBS INCOMING !!",
        EventBanner::Ak => "!! AK BURST !!",
        EventBanner::Rocket => "!! HOMING ROCKET !!",
    };
    if !banner_txt.is_empty() {
        let _ = canvas.draw_text(layout.board_x + 320, 12, banner_txt, 255, 180, 80);
    }

    // Golden apple active text
    if let Some(gf) = gold_food {
        let mut gold_buf = [0u8; 24];
        let gold_txt = format_labeled_u32(&mut gold_buf, "Gold Apple: ", gf.ttl);
        let _ = canvas.draw_text(layout.board_x + 340, 28, gold_txt, 255, 215, 0);
    }

    let board_w = layout.board_w;
    let board_h = layout.board_h;
    let _ = canvas.fill_rect(
        layout.board_x.saturating_sub(4),
        layout.board_y.saturating_sub(4),
        board_w + 8,
        board_h + 8,
        55,
        190,
        205,
    );
    let _ = canvas.fill_rect(
        layout.board_x.saturating_sub(2),
        layout.board_y.saturating_sub(2),
        board_w + 4,
        board_h + 4,
        8,
        20,
        32,
    );
    let _ = canvas.fill_rect(layout.board_x, layout.board_y, board_w, board_h, 7, 14, 24);

    // Sparse grid guides retain a clean look while making the enlarged board
    // readable on high-resolution displays.
    for x in (4..GRID_W).step_by(4) {
        let _ = canvas.fill_rect(
            layout.board_x + x as u32 * layout.cell,
            layout.board_y,
            1,
            board_h,
            12,
            27,
            39,
        );
    }
    for y in (3..GRID_H).step_by(3) {
        let _ = canvas.fill_rect(
            layout.board_x,
            layout.board_y + y as u32 * layout.cell,
            board_w,
            1,
            12,
            27,
            39,
        );
    }

    // Faint red highlight for bomb blast radius when fuse is low
    for b in bombs.iter() {
        if !b.alive {
            continue;
        }
        if b.fuse <= 4 {
            let r = match b.kind {
                BombKind::Small => BOMB_R_SMALL,
                BombKind::Large => BOMB_R_LARGE,
            };
            for dx in -r..=r {
                for dy in -r..=r {
                    let rx = b.pos.x as i16 + dx;
                    let ry = b.pos.y as i16 + dy;
                    if rx >= 0 && rx < GRID_W as i16 && ry >= 0 && ry < GRID_H as i16 {
                        if rx as u8 != b.pos.x || ry as u8 != b.pos.y {
                            let inset = (layout.cell / 4).max(1);
                            let px = layout.board_x + rx as u32 * layout.cell + inset;
                            let py = layout.board_y + ry as u32 * layout.cell + inset;
                            let size = layout.cell.saturating_sub(inset * 2).max(1);
                            let _ = canvas.fill_rect(px, py, size, size, 120, 30, 30);
                        }
                    }
                }
            }
        }
    }

    // Normal Food
    fill_cell(canvas, layout, food.x, food.y, 220, 80, 80);

    // Gold Food
    if let Some(gf) = gold_food {
        let flash = gf.ttl <= 10 && (gf.ttl % 2 == 0);
        if flash {
            fill_cell(canvas, layout, gf.pos.x, gf.pos.y, 100, 80, 0);
        } else {
            fill_cell(canvas, layout, gf.pos.x, gf.pos.y, 255, 215, 0);
        }
    }

    // Bombs (dark with fuse flash)
    for b in bombs.iter() {
        if !b.alive {
            continue;
        }
        let flash = b.fuse <= 3;
        match b.kind {
            BombKind::Small => {
                if flash {
                    fill_cell(canvas, layout, b.pos.x, b.pos.y, 255, 200, 40);
                } else {
                    fill_cell(canvas, layout, b.pos.x, b.pos.y, 60, 60, 70);
                }
            }
            BombKind::Large => {
                if flash {
                    fill_cell(canvas, layout, b.pos.x, b.pos.y, 255, 80, 40);
                } else {
                    fill_cell(canvas, layout, b.pos.x, b.pos.y, 40, 40, 50);
                }
            }
        }
    }

    // Bullets (bright yellow/orange streaks)
    for b in bullets.iter() {
        if b.alive {
            fill_cell(canvas, layout, b.pos.x, b.pos.y, 255, 220, 60);
        }
    }

    // Rocket (magenta diamond-ish block)
    if rocket.alive {
        fill_cell(canvas, layout, rocket.pos.x, rocket.pos.y, 220, 60, 220);
    }

    // Snake with an elegant gradient from bright mint green to deep forest blue-green
    for i in 0..len {
        if i == 0 {
            fill_cell(canvas, layout, body[i].x, body[i].y, 50, 240, 140);
        } else {
            let r = 50 - (30 * i / len) as u8;
            let g = 200 - (100 * i / len) as u8;
            let b = 150 - (90 * i / len) as u8;
            fill_cell(canvas, layout, body[i].x, body[i].y, r, g, b);
        }
    }

    if phase == Phase::GameOver {
        let overlay_y = layout.board_y + board_h.saturating_sub(72) / 2;
        let _ = canvas.fill_rect(layout.board_x, overlay_y, board_w, 72, 18, 4, 10);
        let lose = if hard {
            "You lost at snake! (HARD)"
        } else {
            "You lost at snake!"
        };
        let _ = canvas.draw_text(
            layout.board_x + 24,
            layout.board_y + board_h / 2 - 20,
            lose,
            255,
            120,
            120,
        );
        let _ = canvas.draw_text(
            layout.board_x + 24,
            layout.board_y + board_h / 2,
            "Enter = play again    Esc = shell",
            220,
            220,
            200,
        );
    }

    let _ = canvas.present();
}

fn fill_cell(canvas: &Canvas, layout: &Layout, x: u8, y: u8, r: u8, g: u8, b: u8) {
    let inset = (layout.cell / 10).max(1);
    let px = layout.board_x + x as u32 * layout.cell + inset;
    let py = layout.board_y + y as u32 * layout.cell + inset;
    let size = layout.cell.saturating_sub(inset * 2).max(1);
    let _ = canvas.fill_rect(px, py, size, size, r, g, b);

    // Small highlight gives food, hazards and body segments depth at any
    // resolution without changing collision geometry.
    if size >= 8 {
        let highlight = (size / 5).max(2);
        let _ = canvas.fill_rect(
            px + inset,
            py + inset,
            highlight,
            highlight,
            r.saturating_add(28),
            g.saturating_add(28),
            b.saturating_add(28),
        );
    }
}

/// Write `"<label><value>"` into `buf` and return the UTF-8 slice.
/// no_std / no_alloc friendly — used for HUD text on the framebuffer.
fn format_labeled_u32<'a>(buf: &'a mut [u8], label: &str, mut value: u32) -> &'a str {
    let mut i = 0;
    for &c in label.as_bytes() {
        if i < buf.len() {
            buf[i] = c;
            i += 1;
        }
    }
    if value == 0 {
        if i < buf.len() {
            buf[i] = b'0';
            i += 1;
        }
    } else {
        let mut tmp = [0u8; 10];
        let mut n = 0;
        while value > 0 && n < tmp.len() {
            tmp[n] = b'0' + (value % 10) as u8;
            value /= 10;
            n += 1;
        }
        while n > 0 && i < buf.len() {
            n -= 1;
            buf[i] = tmp[n];
            i += 1;
        }
    }
    core::str::from_utf8(&buf[..i]).unwrap_or("?")
}
