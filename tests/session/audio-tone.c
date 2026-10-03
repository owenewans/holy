/* plays a short sine burst through the audio stack the session already runs and prints what
 * the server accepted. a client that exits cleanly proves nothing on its own, so the case
 * watches the server's sink-input list while this runs and the row claims only what the
 * server listed. the level is low and the burst is short, since a matrix run is not a
 * listening session. */
#define _POSIX_C_SOURCE 200809L

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pulse/simple.h>
#include <pulse/error.h>

#define RATE 44100
#define CHUNK 2048
#define PEAK 3200

int main(int argc, char **argv)
{
    const char *name = argc > 1 ? argv[1] : "holy-matrix-tone";
    double seconds = argc > 2 ? strtod(argv[2], NULL) : 0.4;
    int total;
    int error = 0;
    pa_sample_spec spec;
    pa_buffer_attr attributes;
    pa_simple *stream;
    short *block;
    int written = 0;
    int loudest = 0;

    if (seconds <= 0.0 || seconds > 5.0) {
        fprintf(stderr, "audio-tone: the burst must be between 0 and 5 seconds\n");
        return 2;
    }
    memset(&spec, 0, sizeof spec);
    spec.format = PA_SAMPLE_S16LE;
    spec.rate = RATE;
    spec.channels = 1;
    memset(&attributes, 0, sizeof attributes);
    attributes.maxlength = (uint32_t)-1;
    attributes.tlength = (uint32_t)(seconds * RATE) * 2;
    attributes.fragsize = (uint32_t)-1;
    stream = pa_simple_new(NULL, name, PA_STREAM_PLAYBACK, NULL, "holy matrix tone", &spec, NULL,
                           &attributes, &error);
    if (!stream) {
        fprintf(stderr, "audio-tone: pa_simple_new: %s\n", pa_strerror(error));
        return 1;
    }
    total = (int)(seconds * RATE);
    block = calloc(CHUNK, sizeof *block);
    if (!block) {
        fprintf(stderr, "audio-tone: calloc: out of memory\n");
        pa_simple_free(stream);
        return 1;
    }
    while (written < total) {
        int count = total - written < CHUNK ? total - written : CHUNK;
        int i;
        for (i = 0; i < count; i++) {
            double position = (double)(written + i) / RATE;
            double value = sin(position * 2.0 * 3.14159265358979323846 * 440.0) * PEAK;
            int sample = (int)value;
            if (sample < 0)
                sample = -sample;
            if (sample > loudest)
                loudest = sample;
            block[i] = (short)value;
        }
        if (pa_simple_write(stream, block, (size_t)count * 2, &error) < 0) {
            fprintf(stderr, "audio-tone: pa_simple_write: %s\n", pa_strerror(error));
            free(block);
            pa_simple_free(stream);
            return 1;
        }
        written += count;
    }
    if (pa_simple_drain(stream, &error) < 0) {
        fprintf(stderr, "audio-tone: pa_simple_drain: %s\n", pa_strerror(error));
        free(block);
        pa_simple_free(stream);
        return 1;
    }
    printf("audio-tone name=%s frames=%d rate=%d channels=1 peak=%d\n", name, total, RATE,
           loudest);
    free(block);
    pa_simple_free(stream);
    return 0;
}
