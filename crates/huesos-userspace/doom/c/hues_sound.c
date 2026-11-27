#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "doomtype.h"
#include "i_sound.h"
#include "w_wad.h"
#include "z_zone.h"

int use_libsamplerate = 0;
float libsamplerate_scale = 0.65f;

extern int hues_audio_is_online(void);
extern void hues_audio_blob_begin(void);
extern void hues_audio_blob_push_u64(uint64_t chunk_le, uint32_t valid_bytes);
extern int hues_audio_load_genmidi(void);
extern int hues_audio_cache_sfx(int lumpnum);
extern int hues_audio_start_sfx(int lumpnum, int channel, int vol, int sep);
extern void hues_audio_update_sfx(int channel, int vol, int sep);
extern void hues_audio_stop_sfx(int channel);
extern int hues_audio_sfx_playing(int channel);
extern int hues_audio_register_song(void);
extern void hues_audio_play_song(int looping);
extern void hues_audio_stop_song(void);
extern void hues_audio_pause_song(int paused);
extern void hues_audio_set_music_volume(int vol);
extern int hues_audio_music_playing(void);
extern void hues_audio_pump(void);
extern void hues_audio_shutdown(void);

static void push_bytes_to_rust(const uint8_t *src, int len)
{
    int pos = 0;
    hues_audio_blob_begin();
    if (!src || len <= 0)
    {
        return;
    }
    while (pos < len)
    {
        uint64_t word = 0;
        uint32_t take = (uint32_t)(len - pos);
        uint32_t i;
        if (take > 8)
        {
            take = 8;
        }
        for (i = 0; i < take; ++i)
        {
            word |= ((uint64_t)src[pos + (int)i]) << (i * 8);
        }
        hues_audio_blob_push_u64(word, take);
        pos += (int)take;
    }
}

void I_InitTimidityConfig(void)
{
}

static boolean use_sfx_prefix_flag = true;

static snddevice_t hues_sfx_devices[] = {
    SNDDEVICE_SB,
    SNDDEVICE_PAS,
    SNDDEVICE_GUS,
    SNDDEVICE_WAVEBLASTER,
    SNDDEVICE_SOUNDCANVAS,
    SNDDEVICE_AWE32,
};

static snddevice_t hues_music_devices[] = {
    SNDDEVICE_SB,
    SNDDEVICE_ADLIB,
    SNDDEVICE_PAS,
    SNDDEVICE_GUS,
    SNDDEVICE_WAVEBLASTER,
    SNDDEVICE_SOUNDCANVAS,
    SNDDEVICE_GENMIDI,
    SNDDEVICE_AWE32,
};

static void GetSfxLumpName(sfxinfo_t *sfx, char *buf, size_t buf_len)
{
    if (sfx->link != NULL)
    {
        sfx = sfx->link;
    }
    if (use_sfx_prefix_flag)
    {
        snprintf(buf, buf_len, "ds%s", sfx->name);
    }
    else
    {
        snprintf(buf, buf_len, "%s", sfx->name);
    }
}

static boolean Hues_SFX_Init(boolean use_sfx_prefix)
{
    int genmidi_lump;
    use_sfx_prefix_flag = use_sfx_prefix;
    if (!hues_audio_is_online())
    {
        return false;
    }
    genmidi_lump = W_CheckNumForName("GENMIDI");
    if (genmidi_lump >= 0)
    {
        int len = W_LumpLength(genmidi_lump);
        const uint8_t *data = (const uint8_t *)W_CacheLumpNum(genmidi_lump, PU_STATIC);
        push_bytes_to_rust(data, len);
        hues_audio_load_genmidi();
        W_ReleaseLumpNum(genmidi_lump);
    }
    return true;
}

static void Hues_SFX_Shutdown(void)
{
    hues_audio_shutdown();
}

static int Hues_SFX_GetSfxLumpNum(sfxinfo_t *sfx)
{
    char namebuf[16];
    GetSfxLumpName(sfx, namebuf, sizeof(namebuf));
    return W_GetNumForName(namebuf);
}

static void Hues_SFX_Update(void)
{
    hues_audio_pump();
}

static void Hues_SFX_UpdateSoundParams(int channel, int vol, int sep)
{
    hues_audio_update_sfx(channel, vol, sep);
}

static void ensure_sfx_cached(int lumpnum)
{
    if (lumpnum < 0)
    {
        return;
    }
    if (!hues_audio_cache_sfx(lumpnum))
    {
        int len = W_LumpLength(lumpnum);
        const uint8_t *data = (const uint8_t *)W_CacheLumpNum(lumpnum, PU_STATIC);
        push_bytes_to_rust(data, len);
        (void)hues_audio_cache_sfx(lumpnum);
        W_ReleaseLumpNum(lumpnum);
    }
}

static int Hues_SFX_StartSound(sfxinfo_t *sfxinfo, int channel, int vol, int sep)
{
    int lumpnum;
    if (!sfxinfo || channel < 0)
    {
        return -1;
    }
    lumpnum = sfxinfo->lumpnum;
    if (lumpnum < 0)
    {
        lumpnum = Hues_SFX_GetSfxLumpNum(sfxinfo);
        sfxinfo->lumpnum = lumpnum;
    }
    ensure_sfx_cached(lumpnum);
    return hues_audio_start_sfx(lumpnum, channel, vol, sep);
}

static void Hues_SFX_StopSound(int channel)
{
    hues_audio_stop_sfx(channel);
}

static boolean Hues_SFX_SoundIsPlaying(int channel)
{
    return hues_audio_sfx_playing(channel) ? true : false;
}

static void Hues_SFX_CacheSounds(sfxinfo_t *sounds, int num_sounds)
{
    int i;
    for (i = 0; i < num_sounds; ++i)
    {
        char namebuf[16];
        int lumpnum;
        GetSfxLumpName(&sounds[i], namebuf, sizeof(namebuf));
        lumpnum = W_CheckNumForName(namebuf);
        if (lumpnum >= 0)
        {
            sounds[i].lumpnum = lumpnum;
            ensure_sfx_cached(lumpnum);
        }
    }
}

sound_module_t DG_sound_module = {
    hues_sfx_devices,
    (int)(sizeof(hues_sfx_devices) / sizeof(hues_sfx_devices[0])),
    Hues_SFX_Init,
    Hues_SFX_Shutdown,
    Hues_SFX_GetSfxLumpNum,
    Hues_SFX_Update,
    Hues_SFX_UpdateSoundParams,
    Hues_SFX_StartSound,
    Hues_SFX_StopSound,
    Hues_SFX_SoundIsPlaying,
    Hues_SFX_CacheSounds,
};

static int dummy_song_token = 1;

static boolean Hues_Music_Init(void)
{
    return hues_audio_is_online() ? true : false;
}

static void Hues_Music_Shutdown(void)
{
    hues_audio_stop_song();
}

static void Hues_Music_SetMusicVolume(int volume)
{
    hues_audio_set_music_volume(volume);
}

static void Hues_Music_PauseSong(void)
{
    hues_audio_pause_song(1);
}

static void Hues_Music_ResumeSong(void)
{
    hues_audio_pause_song(0);
}

static void *Hues_Music_RegisterSong(void *data, int len)
{
    if (!data || len <= 0)
    {
        return NULL;
    }
    push_bytes_to_rust((const uint8_t *)data, len);
    if (!hues_audio_register_song())
    {
        return NULL;
    }
    return &dummy_song_token;
}

static void Hues_Music_UnRegisterSong(void *handle)
{
    (void)handle;
    hues_audio_stop_song();
}

static void Hues_Music_PlaySong(void *handle, boolean looping)
{
    if (!handle)
    {
        return;
    }
    hues_audio_play_song(looping ? 1 : 0);
}

static void Hues_Music_StopSong(void)
{
    hues_audio_stop_song();
}

static boolean Hues_Music_MusicIsPlaying(void)
{
    return hues_audio_music_playing() ? true : false;
}

static void Hues_Music_Poll(void)
{
    hues_audio_pump();
}

music_module_t DG_music_module = {
    hues_music_devices,
    (int)(sizeof(hues_music_devices) / sizeof(hues_music_devices[0])),
    Hues_Music_Init,
    Hues_Music_Shutdown,
    Hues_Music_SetMusicVolume,
    Hues_Music_PauseSong,
    Hues_Music_ResumeSong,
    Hues_Music_RegisterSong,
    Hues_Music_UnRegisterSong,
    Hues_Music_PlaySong,
    Hues_Music_StopSong,
    Hues_Music_MusicIsPlaying,
    Hues_Music_Poll,
};
