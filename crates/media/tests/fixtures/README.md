# Test-only fixture provenance

These small fixtures were created locally for this test suite from a solid blue image and digital silence. They contain no captured service media, user content, account material or third-party creative work. They are dedicated to CC0-1.0. Neither fixture is linked into the production library or executable.

Video generation:

```sh
ffmpeg -v error -y -f lavfi -i 'color=c=blue:s=64x64:r=60' \
  -frames:v 6 -an -c:v libx264 -profile:v baseline -pix_fmt yuv420p \
  -color_range tv -colorspace bt709 -color_primaries bt709 -color_trc bt709 \
  -chroma_sample_location left \
  -x264-params 'keyint=1:repeat-headers=1:scenecut=0:chromaloc=0:force-cfr=1' \
  -f h264 blue-64x64-bt709.h264
```

Audio was encoded with the following command, then its first media packet was extracted by reading Ogg page lacing and skipping OpusHead/OpusTags. The retained packet is three bytes and represents a 20 ms stereo Opus silence frame. Tests pass those original encoder bytes through SRTP; they do not substitute PCM or fabricate an Opus header.

```sh
ffmpeg -v error -y -f lavfi -i 'anullsrc=r=48000:cl=stereo' \
  -t 0.02 -c:a libopus -frame_duration 20 -f ogg fixture.ogg
```

The test parser verifies the SPS/VUI fixed frame-rate ratio as 60 fps and the explicit BT.709 limited-range metadata. ffprobe's guessed raw-stream `r_frame_rate` reports 120 for this all-IDR fixture, so the tests intentionally check encoded SPS timing instead of treating ffprobe's stream guess as service evidence. No fixture is a Boosteroid compatibility capture.
