//! Simple TUI Snake for the HuesOS terminal.
//!
//! Classic: `snake` — normal pace, no hazards.
//! Hard:    `snake hard` — every 2 apples a random event:
//!   1) Bombs (small / large blast radius)
//!   2) Kalash short burst across a row/col
//!   3) Homing rocket that chases the head for ~3s
//!
//! Controls: WASD/HJKL, Enter restart, Esc quit to shell.

use libcanvas::framebuffer::Canvas;
use libcanvas::{Channel, ErrorCode};

const GRID_W: usize = 32;
const GRID_H: usize = 18;
const MAX_LEN: usize = GRID_W * GRID_H;
const CELL: u32 = 16;
const MARGIN_X: u32 = 40;
const MARGIN_Y: u32 = 48;

// --- FIXED snake FPS via Kernel Sleep Timeout & RDTSC --------------------
// Target: ~10 steps/s classic Snake (100 ms/step), floor 60 ms.
// 1 tick = 10 ms (100 Hz timer), so BASE_STEP_TICKS = 10 (100 ms).
const BASE_STEP_TICKS: u64 = 10;
const MIN_STEP_TICKS: u64 = 6;

// Hard-mode events.
const MAX_BOMBS: usize = 6;
const MAX_BULLETS: usize = 16;
/// ~3 seconds of rocket chase at ~10 steps/s.
const ROCKET_LIFE_STEPS: u32 = 30;
/// Bomb fuse in snake steps.
const BOMB_FUSE_SMALL: u32 = 12;
const BOMB_FUSE_LARGE: u32 = 16;
const BOMB_R_SMALL: i16 = 1;
const BOMB_R_LARGE: i16 = 2;
/// Kalash: bullets advance every snake step.
const KALASH_BURST: usize = 5;

#[inline]
fn rdtsc() -> u64 {
    let lo: u32;
    let hi: u32;
    // SAFETY: rdtsc is unprivileged on long-mode x86_64 with default CR4.
    unsafe {
        core::arch::asm!(
            "rdtsc",
            out("eax") lo,
            out("edx") hi,
            options(nomem, nostack, preserves_flags)
        );
    }
    ((hi as u64) << 32) | (lo as u64)
}

/// Calibrate the TSC frequency against the kernel's scheduler ticks.
/// Sleep for 10 ticks (100 ms) and measure the elapsed RDTSC cycles.
/// This method retries if interrupted by a key press, ensuring a highly robust,
/// sleep-free equivalent of precise calibration at terminal startup.
fn calibrate_tsc(keyboard: &Channel) -> u64 {
    let mut buf = [0u8; 16];

    // Drain any pending input first
    for _ in 0..100 {
        match keyboard.read_into(&mut buf) {
            Ok(n) if n > 0 => {}
            _ => break,
        }
    }

    // Try up to 5 times to get an uninterrupted 10-tick sleep
    for _ in 0..5 {
        let start = rdtsc();
        match keyboard.read_into_timeout(&mut buf, 10) {
            Err(ErrorCode::TimedOut) => {
                let end = rdtsc();
                let elapsed = end.wrapping_sub(start);
                let mut cycles_per_tick = elapsed / 10;

                // Safety clamps for 0.5 GHz to 10.0 GHz
                if cycles_per_tick < 5_000_000 {
                    cycles_per_tick = 30_000_000; // default to 3.0 GHz
                } else if cycles_per_tick > 100_000_000 {
                    cycles_per_tick = 40_000_000; // default to 4.0 GHz
                }
                return cycles_per_tick;
            }
            _ => {
                // If interrupted by a key press, drain keys and try again
                for _ in 0..10 {
                    let _ = keyboard.read_into(&mut buf);
                }
            }
        }
    }

    // Default fallback (assuming 4.0 GHz TSC rate)
    40_000_000
}

fn step_delay_ticks(score: u32) -> u64 {
    // Mild speed-up: every 5 food, -1 tick/10 ms, never below MIN_STEP_TICKS.
    let faster_ticks = score as u64 / 5;
    BASE_STEP_TICKS
        .saturating_sub(faster_ticks)
        .max(MIN_STEP_TICKS)
}

/// Wait one snake-step, sleeping the thread in 1-tick (10ms) increments
/// while verifying exact elapsed wall-clock time using RDTSC.
/// Drains keyboard events on every loop iteration to guarantee zero input latency.
fn wait_step(
    score: u32,
    keyboard: &Channel,
    dir: Dir,
    pending: &mut Dir,
    phase: Phase,
    cycles_per_tick: u64,
) -> Option<Action> {
    let step_ticks = step_delay_ticks(score);
    let step_cycles = step_ticks * cycles_per_tick;
    let start_cycles = rdtsc();
    let mut buf = [0u8; 16];

    loop {
        let now_cycles = rdtsc();
        let elapsed_cycles = now_cycles.wrapping_sub(start_cycles);
        if elapsed_cycles >= step_cycles {
            return None;
        }

        // Non-blocking keyboard drain (instantly process user turns)
        loop {
            match keyboard.read_into(&mut buf) {
                Ok(n) if n > 0 => {
                    if let Some(action) = decode(&buf[..n]) {
                        match phase {
                            Phase::Playing => match action {
                                Action::Dir(d) => {
                                    // Reject a turn that would reverse either the
                                    // committed direction OR an already-queued one.
                                    // Without the second check, pressing Up then
                                    // Down within a single step while moving Right
                                    // would accept Down (not opposite to Right) and
                                    // the snake would eat its own neck next tick.
                                    if !is_opposite(dir, d) && !is_opposite(*pending, d) {
                                        *pending = d;
                                    }
                                }
                                Action::Esc => return Some(Action::Esc),
                                Action::Enter => {}
                            },
                            Phase::GameOver => match action {
                                Action::Enter | Action::Esc => return Some(action),
                                Action::Dir(_) => {}
                            },
                        }
                    }
                }
                _ => break,
            }
        }

        // Double check elapsed time after handling keys
        let now_cycles = rdtsc();
        let elapsed_cycles = now_cycles.wrapping_sub(start_cycles);
        if elapsed_cycles >= step_cycles {
            return None;
        }

        // Sleep for a tiny interval (1 tick = 10 ms) to keep CPU at 0% idle consumption
        let _ = keyboard.read_into_timeout(&mut buf, 1);
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
    Kalash,
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

    let cycles_per_tick = calibrate_tsc(keyboard);

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
        &canvas, hard, &body, len, food, gold_food, phase, score, &bombs, &bullets, &rocket, banner,
    );

    loop {
        // Wait one paced step, polling keys the whole time via blocking timeouts.
        if let Some(action) = wait_step(score, keyboard, dir, &mut pending, phase, cycles_per_tick)
        {
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
                            &canvas, hard, &body, len, food, gold_food, phase, score, &bombs,
                            &bullets, &rocket, banner,
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
            if !tick_hazards(&mut bombs, &mut bullets, &mut rocket, &body, len, &mut rng) {
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
            &canvas, hard, &body, len, food, gold_food, phase, score, &bombs, &bullets, &rocket,
            banner,
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
            // Kalash burst from a board edge toward the head row/col
            *banner = EventBanner::Kalash;
            *banner_ttl = 14;
            fire_kalash(rng, body, bullets);
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

fn fire_kalash(rng: &mut u32, body: &[Point; MAX_LEN], bullets: &mut [Bullet; MAX_BULLETS]) {
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
        if placed >= KALASH_BURST {
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

    // Bullets fly one cell per step
    for b in bullets.iter_mut() {
        if !b.alive {
            continue;
        }
        if on_snake(body, len, b.pos) {
            b.alive = false;
            return false;
        }
        match step_point(b.pos, b.dir) {
            Some(np) => {
                b.pos = np;
                if on_snake(body, len, b.pos) {
                    b.alive = false;
                    return false;
                }
            }
            None => b.alive = false,
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
    let _ = canvas.fill_rect(0, 0, canvas.width(), canvas.height(), 8, 12, 20);

    let title = if hard {
        "HuesOS Snake  [HARD]"
    } else {
        "HuesOS Snake"
    };
    let _ = canvas.draw_text(MARGIN_X, 12, title, 200, 230, 255);
    let mut score_buf = [0u8; 24];
    let score_txt = format_score(&mut score_buf, score);
    let _ = canvas.draw_text(MARGIN_X + 220, 12, score_txt, 180, 220, 160);

    let help = if hard {
        "WASD move | Esc quit | every 2 apples: random hazard"
    } else {
        "WASD/HJKL move | Esc quit | try: snake hard"
    };
    let _ = canvas.draw_text(MARGIN_X, 28, help, 140, 160, 180);

    // Event banner
    let banner_txt = match banner {
        EventBanner::None => "",
        EventBanner::Bombs => "!! BOMBS INCOMING !!",
        EventBanner::Kalash => "!! KALASH BURST !!",
        EventBanner::Rocket => "!! HOMING ROCKET !!",
    };
    if !banner_txt.is_empty() {
        let _ = canvas.draw_text(MARGIN_X + 320, 12, banner_txt, 255, 180, 80);
    }

    // Golden apple active text
    if let Some(gf) = gold_food {
        let mut gold_buf = [0u8; 24];
        let gold_txt = format_gold_ttl(&mut gold_buf, gf.ttl);
        let _ = canvas.draw_text(MARGIN_X + 340, 28, gold_txt, 255, 215, 0);
    }

    let board_w = GRID_W as u32 * CELL;
    let board_h = GRID_H as u32 * CELL;
    let _ = canvas.fill_rect(
        MARGIN_X.saturating_sub(2),
        MARGIN_Y.saturating_sub(2),
        board_w + 4,
        board_h + 4,
        30,
        40,
        55,
    );
    let _ = canvas.fill_rect(MARGIN_X, MARGIN_Y, board_w, board_h, 12, 18, 28);

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
                            let px = MARGIN_X + rx as u32 * CELL + 4;
                            let py = MARGIN_Y + ry as u32 * CELL + 4;
                            let _ = canvas.fill_rect(px, py, CELL - 8, CELL - 8, 120, 30, 30);
                        }
                    }
                }
            }
        }
    }

    // Normal Food
    fill_cell(canvas, food.x, food.y, 220, 80, 80);

    // Gold Food
    if let Some(gf) = gold_food {
        let flash = gf.ttl <= 10 && (gf.ttl % 2 == 0);
        if flash {
            fill_cell(canvas, gf.pos.x, gf.pos.y, 100, 80, 0);
        } else {
            fill_cell(canvas, gf.pos.x, gf.pos.y, 255, 215, 0);
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
                    fill_cell(canvas, b.pos.x, b.pos.y, 255, 200, 40);
                } else {
                    fill_cell(canvas, b.pos.x, b.pos.y, 60, 60, 70);
                }
            }
            BombKind::Large => {
                if flash {
                    fill_cell(canvas, b.pos.x, b.pos.y, 255, 80, 40);
                } else {
                    fill_cell(canvas, b.pos.x, b.pos.y, 40, 40, 50);
                }
            }
        }
    }

    // Bullets (bright yellow/orange streaks)
    for b in bullets.iter() {
        if b.alive {
            fill_cell(canvas, b.pos.x, b.pos.y, 255, 220, 60);
        }
    }

    // Rocket (magenta diamond-ish block)
    if rocket.alive {
        fill_cell(canvas, rocket.pos.x, rocket.pos.y, 220, 60, 220);
    }

    // Snake with an elegant gradient from bright mint green to deep forest blue-green
    for i in 0..len {
        if i == 0 {
            fill_cell(canvas, body[i].x, body[i].y, 50, 240, 140);
        } else {
            let r = 50 - (30 * i / len) as u8;
            let g = 200 - (100 * i / len) as u8;
            let b = 150 - (90 * i / len) as u8;
            fill_cell(canvas, body[i].x, body[i].y, r, g, b);
        }
    }

    if phase == Phase::GameOver {
        let _ = canvas.fill_rect(MARGIN_X, MARGIN_Y + board_h / 2 - 28, board_w, 56, 0, 0, 0);
        let lose = if hard {
            "You lost at snake! (HARD)"
        } else {
            "You lost at snake!"
        };
        let _ = canvas.draw_text(
            MARGIN_X + 24,
            MARGIN_Y + board_h / 2 - 20,
            lose,
            255,
            120,
            120,
        );
        let _ = canvas.draw_text(
            MARGIN_X + 24,
            MARGIN_Y + board_h / 2,
            "Enter = play again    Esc = shell",
            220,
            220,
            200,
        );
    }

    let _ = canvas.present();
}

fn fill_cell(canvas: &Canvas, x: u8, y: u8, r: u8, g: u8, b: u8) {
    let px = MARGIN_X + x as u32 * CELL + 1;
    let py = MARGIN_Y + y as u32 * CELL + 1;
    let _ = canvas.fill_rect(px, py, CELL - 2, CELL - 2, r, g, b);
}

fn format_score(buf: &mut [u8], mut score: u32) -> &str {
    let prefix = b"Score: ";
    let mut i = 0;
    for &c in prefix {
        if i < buf.len() {
            buf[i] = c;
            i += 1;
        }
    }
    if score == 0 {
        if i < buf.len() {
            buf[i] = b'0';
            i += 1;
        }
    } else {
        let mut tmp = [0u8; 10];
        let mut n = 0;
        while score > 0 && n < tmp.len() {
            tmp[n] = b'0' + (score % 10) as u8;
            score /= 10;
            n += 1;
        }
        while n > 0 && i < buf.len() {
            n -= 1;
            buf[i] = tmp[n];
            i += 1;
        }
    }
    core::str::from_utf8(&buf[..i]).unwrap_or("Score: ?")
}

fn format_gold_ttl(buf: &mut [u8], mut score: u32) -> &str {
    let prefix = b"Gold Apple: ";
    let mut i = 0;
    for &c in prefix {
        if i < buf.len() {
            buf[i] = c;
            i += 1;
        }
    }
    if score == 0 {
        if i < buf.len() {
            buf[i] = b'0';
            i += 1;
        }
    } else {
        let mut tmp = [0u8; 10];
        let mut n = 0;
        while score > 0 && n < tmp.len() {
            tmp[n] = b'0' + (score % 10) as u8;
            score /= 10;
            n += 1;
        }
        while n > 0 && i < buf.len() {
            n -= 1;
            buf[i] = tmp[n];
            i += 1;
        }
    }
    core::str::from_utf8(&buf[..i]).unwrap_or("Gold Apple: ?")
}
