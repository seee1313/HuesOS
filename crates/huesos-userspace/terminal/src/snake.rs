//! Simple TUI Snake for the HuesOS terminal.
//!
//! Controls: WASD (or HJKL) to move, Enter to restart after loss, Esc to quit
//! back to the shell. Self-contained canvas UI — does not share the shell
//! text buffer.

use libcanvas::framebuffer::Canvas;
use libcanvas::{Channel, ErrorCode};

const GRID_W: usize = 32;
const GRID_H: usize = 18;
const MAX_LEN: usize = GRID_W * GRID_H;
const CELL: u32 = 16;
const MARGIN_X: u32 = 40;
const MARGIN_Y: u32 = 48;
const TICK_YIELDS: u32 = 12; // ~game speed under cooperative yield

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

/// Run Snake until the player presses Esc from the game-over screen
/// (or Esc during play to quit immediately).
pub fn run(keyboard: &Channel) {
    let Ok(canvas) = Canvas::new_fullscreen() else {
        // Serial-only: nothing to draw.
        return;
    };

    let mut body = [Point { x: 0, y: 0 }; MAX_LEN];
    let mut len = 0usize;
    let mut dir = Dir::Right;
    let mut pending = Dir::Right;
    let mut food = Point { x: 10, y: 8 };
    let mut phase = Phase::Playing;
    let mut score = 0u32;
    let mut tick = 0u32;
    let mut rng = 0xA5A5_1234u32;

    reset(&mut body, &mut len, &mut dir, &mut pending, &mut food, &mut score, &mut phase, &mut rng);
    draw(&canvas, &body, len, food, phase, score);

    let mut buf = [0u8; 16];
    loop {
        // Drain keyboard (non-blocking) every frame.
        loop {
            match keyboard.read_into(&mut buf) {
                Ok(n) => {
                    if let Some(action) = decode(&buf[..n]) {
                        match phase {
                            Phase::Playing => match action {
                                Action::Dir(d) => {
                                    if !is_opposite(dir, d) {
                                        pending = d;
                                    }
                                }
                                Action::Esc => return,
                                Action::Enter => {}
                            },
                            Phase::GameOver => match action {
                                Action::Enter => {
                                    reset(
                                        &mut body,
                                        &mut len,
                                        &mut dir,
                                        &mut pending,
                                        &mut food,
                                        &mut score,
                                        &mut phase,
                                        &mut rng,
                                    );
                                    draw(&canvas, &body, len, food, phase, score);
                                }
                                Action::Esc => return,
                                Action::Dir(_) => {}
                            },
                        }
                    }
                }
                Err(ErrorCode::ShouldWait) => break,
                Err(_) => {
                    libcanvas::process::yield_now();
                    break;
                }
            }
        }

        if phase == Phase::Playing {
            tick = tick.wrapping_add(1);
            if tick >= TICK_YIELDS {
                tick = 0;
                dir = pending;
                if !step(&mut body, &mut len, dir, &mut food, &mut score, &mut rng) {
                    phase = Phase::GameOver;
                }
                draw(&canvas, &body, len, food, phase, score);
            }
        }

        libcanvas::process::yield_now();
    }
}

fn reset(
    body: &mut [Point; MAX_LEN],
    len: &mut usize,
    dir: &mut Dir,
    pending: &mut Dir,
    food: &mut Point,
    score: &mut u32,
    phase: &mut Phase,
    rng: &mut u32,
) {
    body[0] = Point { x: 8, y: 8 };
    body[1] = Point { x: 7, y: 8 };
    body[2] = Point { x: 6, y: 8 };
    *len = 3;
    *dir = Dir::Right;
    *pending = Dir::Right;
    *score = 0;
    *phase = Phase::Playing;
    *food = spawn_food(body, *len, rng);
}

fn step(
    body: &mut [Point; MAX_LEN],
    len: &mut usize,
    dir: Dir,
    food: &mut Point,
    score: &mut u32,
    rng: &mut u32,
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
    // Hit self?
    for i in 0..*len {
        if body[i].x == next.x && body[i].y == next.y {
            return false;
        }
    }
    // Grow or slide.
    let eat = next.x == food.x && next.y == food.y;
    if eat {
        if *len + 1 < MAX_LEN {
            *len += 1;
        }
        *score = score.saturating_add(1);
    }
    // Shift body towards tail.
    let mut i = *len - 1;
    while i > 0 {
        body[i] = body[i - 1];
        i -= 1;
    }
    body[0] = next;
    if eat {
        *food = spawn_food(body, *len, rng);
    }
    true
}

fn spawn_food(body: &[Point; MAX_LEN], len: usize, rng: &mut u32) -> Point {
    for _ in 0..256 {
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
            27 => Some(Action::Esc), // ESC scancode → ASCII ESC
            _ => None,
        },
        b"enter" => Some(Action::Enter),
        b"backspace" => None,
        _ => None,
    }
}

fn draw(
    canvas: &Canvas,
    body: &[Point; MAX_LEN],
    len: usize,
    food: Point,
    phase: Phase,
    score: u32,
) {
    let _ = canvas.fill_rect(0, 0, canvas.width(), canvas.height(), 8, 12, 20);

    // Title / score
    let _ = canvas.draw_text(MARGIN_X, 16, "HuesOS Snake", 200, 230, 255);
    let mut score_buf = [0u8; 24];
    let score_txt = format_score(&mut score_buf, score);
    let _ = canvas.draw_text(MARGIN_X + 200, 16, score_txt, 180, 220, 160);
    let _ = canvas.draw_text(
        MARGIN_X,
        32,
        "WASD/HJKL move  |  Esc quit",
        140,
        160,
        180,
    );

    // Board background
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

    // Food
    fill_cell(canvas, food.x, food.y, 220, 80, 80);
    // Snake
    for i in 0..len {
        if i == 0 {
            fill_cell(canvas, body[i].x, body[i].y, 80, 220, 120);
        } else {
            fill_cell(canvas, body[i].x, body[i].y, 40, 170, 90);
        }
    }

    if phase == Phase::GameOver {
        // Dim overlay strip
        let _ = canvas.fill_rect(
            MARGIN_X,
            MARGIN_Y + board_h / 2 - 28,
            board_w,
            56,
            0,
            0,
            0,
        );
        let _ = canvas.draw_text(
            MARGIN_X + 24,
            MARGIN_Y + board_h / 2 - 20,
            "You lost at snake!",
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
    // "Score: N"
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
