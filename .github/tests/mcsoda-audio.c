#include <windows.h>
#include <mmsystem.h>
#include <stdio.h>

static short samples[11025];

int main(void)
{
    WAVEFORMATEX format = {0};
    WAVEHDR header = {0};
    HWAVEOUT output;
    MMRESULT result;
    unsigned int i;

    if (!waveOutGetNumDevs()) return 1;

    format.wFormatTag = WAVE_FORMAT_PCM;
    format.nChannels = 1;
    format.nSamplesPerSec = 44100;
    format.wBitsPerSample = 16;
    format.nBlockAlign = format.nChannels * format.wBitsPerSample / 8;
    format.nAvgBytesPerSec = format.nSamplesPerSec * format.nBlockAlign;

    result = waveOutOpen(&output, WAVE_MAPPER, &format, 0, 0, CALLBACK_NULL);
    if (result != MMSYSERR_NOERROR) return 2;

    for (i = 0; i < sizeof(samples) / sizeof(samples[0]); ++i)
        samples[i] = (i / 50) % 2 ? 3000 : -3000;

    header.lpData = (char *)samples;
    header.dwBufferLength = sizeof(samples);
    result = waveOutPrepareHeader(output, &header, sizeof(header));
    if (result != MMSYSERR_NOERROR) return 3;

    result = waveOutWrite(output, &header, sizeof(header));
    if (result != MMSYSERR_NOERROR) return 4;

    for (i = 0; i < 500 && !(header.dwFlags & WHDR_DONE); ++i) Sleep(10);
    if (!(header.dwFlags & WHDR_DONE)) return 5;

    if (waveOutUnprepareHeader(output, &header, sizeof(header)) != MMSYSERR_NOERROR) return 6;
    if (waveOutClose(output) != MMSYSERR_NOERROR) return 7;

    puts("McSoda audio test");
    return 0;
}
