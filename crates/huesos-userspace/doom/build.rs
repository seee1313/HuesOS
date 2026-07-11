use std::path::PathBuf;

fn main() {
    let root = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let doom = root.join("../../../third_party/doomgeneric");
    let sources = [
        "dummy.c", "am_map.c", "doomdef.c", "doomstat.c", "dstrings.c",
        "d_event.c", "d_items.c", "d_iwad.c", "d_loop.c", "d_main.c",
        "d_mode.c", "d_net.c", "f_finale.c", "f_wipe.c", "g_game.c",
        "hu_lib.c", "hu_stuff.c", "info.c", "i_cdmus.c", "i_endoom.c",
        "i_joystick.c", "i_scale.c", "i_sound.c", "i_system.c", "i_timer.c",
        "memio.c", "m_argv.c", "m_bbox.c", "m_cheat.c", "m_config.c",
        "m_controls.c", "m_fixed.c", "m_menu.c", "m_misc.c", "m_random.c",
        "p_ceilng.c", "p_doors.c", "p_enemy.c", "p_floor.c", "p_inter.c",
        "p_lights.c", "p_map.c", "p_maputl.c", "p_mobj.c", "p_plats.c",
        "p_pspr.c", "p_saveg.c", "p_setup.c", "p_sight.c", "p_spec.c",
        "p_switch.c", "p_telept.c", "p_tick.c", "p_user.c", "r_bsp.c",
        "r_data.c", "r_draw.c", "r_main.c", "r_plane.c", "r_segs.c",
        "r_sky.c", "r_things.c", "sha1.c", "sounds.c", "statdump.c",
        "st_lib.c", "st_stuff.c", "s_sound.c", "tables.c", "v_video.c",
        "wi_stuff.c", "w_checksum.c", "w_file.c", "w_main.c", "w_wad.c",
        "z_zone.c", "w_file_stdc.c", "i_input.c", "i_video.c", "doomgeneric.c",
    ];

    let mut build = cc::Build::new();
    build
        .compiler("gcc")
        .include(&doom)
        .include(root.join("c/include"))
        .flag("-ffreestanding")
        .flag("-fno-builtin")
        .flag("-fno-stack-protector")
        .flag("-fno-pic")
        .flag("-mno-red-zone")
        .define("NORMALUNIX", None)
        .define("DOOMGENERIC_RESX", "640")
        .define("DOOMGENERIC_RESY", "400")
        .warnings(false);
    for source in &sources {
        build.file(doom.join(source));
    }
    build.file(root.join("c/hues_libc.c"));
    build.compile("doomgeneric_huesos");

    for source in &sources {
        println!("cargo:rerun-if-changed={}", doom.join(source).display());
    }
    println!("cargo:rerun-if-changed=c/hues_libc.c");
    println!("cargo:rerun-if-changed=c/include");
    println!("cargo:rerun-if-changed=src/main.rs");
}
