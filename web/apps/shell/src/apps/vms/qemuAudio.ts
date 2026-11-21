/**
 * The VM's sound in the web console (decision 418): QEMU's VNC audio
 * extension, which noVNC doesn't speak. The client asks for pseudo-encoding
 * -259, QEMU acknowledges with an empty rectangle of that encoding, and once
 * the client sends "set format" and "enable" (QEMU client message 255,
 * submessage 1) QEMU sends audio messages: 255, 1, u16 operation (0 end,
 * 1 begin, 2 data with a u32 length). Samples are signed 16-bit,
 * little-endian, interleaved.
 */

export const QEMU_AUDIO_ENCODING = -259;
export const AUDIO_RATE = 44100;
export const AUDIO_CHANNELS = 2;
/** The largest audio message accepted (QEMU sends a few KB at a time). */
export const MAX_AUDIO_CHUNK = 1 << 20;

const FORMAT_S16 = 3;

/** The client messages that turn sound on: set format, then enable. */
export function audioOnMessages(rate = AUDIO_RATE, channels = AUDIO_CHANNELS): Uint8Array {
  const b = new Uint8Array(10 + 4);
  const v = new DataView(b.buffer);
  b.set([255, 1, 0, 2, FORMAT_S16, channels]);
  v.setUint32(6, rate);
  b.set([255, 1, 0, 0], 10);
  return b;
}

/** The client message that turns sound off. */
export function audioOffMessage(): Uint8Array {
  return new Uint8Array([255, 1, 0, 1]);
}

export type AudioEvent = { kind: "begin" } | { kind: "end" } | { kind: "data"; data: Uint8Array };
export type ParseResult = { need: true } | { need: false; consumed: number; event: AudioEvent } | { error: string };

/** Reads one QEMU server message (type 255) from the start of buf. */
export function parseAudio(buf: Uint8Array): ParseResult {
  if (buf.length < 4) return { need: true };
  if (buf[0] !== 255) return { error: "not a QEMU message" };
  if (buf[1] !== 1) return { error: `unknown QEMU server message ${buf[1]}` };
  const op = (buf[2]! << 8) | buf[3]!;
  if (op === 0) return { need: false, consumed: 4, event: { kind: "end" } };
  if (op === 1) return { need: false, consumed: 4, event: { kind: "begin" } };
  if (op !== 2) return { error: `unknown QEMU audio operation ${op}` };
  if (buf.length < 8) return { need: true };
  const len = new DataView(buf.buffer, buf.byteOffset, buf.byteLength).getUint32(4);
  if (len > MAX_AUDIO_CHUNK) return { error: "an audio message is too big" };
  if (buf.length < 8 + len) return { need: true };
  return { need: false, consumed: 8 + len, event: { kind: "data", data: buf.slice(8, 8 + len) } };
}

/** Splits interleaved signed 16-bit little-endian samples into channels of floats. */
export function s16leToChannels(data: Uint8Array, channels = AUDIO_CHANNELS): Float32Array<ArrayBuffer>[] {
  const frames = Math.floor(data.length / (2 * channels));
  const out = Array.from({ length: channels }, () => new Float32Array(new ArrayBuffer(frames * 4)));
  const v = new DataView(data.buffer, data.byteOffset, data.byteLength);
  for (let i = 0; i < frames; i++) {
    for (let c = 0; c < channels; c++) {
      out[c]![i] = v.getInt16((i * channels + c) * 2, true) / 32768;
    }
  }
  return out;
}

/** Plays chunks as they come, a little behind to absorb jitter. */
export class AudioPlayer {
  private ctx: AudioContext | null = null;
  private next = 0;

  start() {
    if (this.ctx) return;
    const Ctx = window.AudioContext ?? (window as unknown as { webkitAudioContext?: typeof AudioContext }).webkitAudioContext;
    if (!Ctx) return;
    this.ctx = new Ctx({ sampleRate: AUDIO_RATE });
    this.next = 0;
  }

  play(data: Uint8Array) {
    const ctx = this.ctx;
    if (!ctx) return;
    const chans = s16leToChannels(data);
    const frames = chans[0]?.length ?? 0;
    if (frames === 0) return;
    const buf = ctx.createBuffer(AUDIO_CHANNELS, frames, AUDIO_RATE);
    chans.forEach((c, i) => buf.copyToChannel(c, i));
    const src = ctx.createBufferSource();
    src.buffer = buf;
    src.connect(ctx.destination);
    const now = ctx.currentTime;
    // Too far behind (or too far ahead): start again just ahead of now.
    if (this.next < now || this.next > now + 0.5) this.next = now + 0.08;
    src.start(this.next);
    this.next += buf.duration;
  }

  stop() {
    void this.ctx?.close();
    this.ctx = null;
  }
}

/* eslint-disable @typescript-eslint/no-explicit-any */
type RFBConstructor = new (...args: any[]) => any;

/**
 * An RFB (noVNC) subclass that also speaks QEMU's audio extension. The
 * hooks use noVNC's internal methods (pinned noVNC 1.7.0); anything that
 * doesn't look like an audio message goes to noVNC as before.
 */
export function withQemuAudio<T extends RFBConstructor>(Base: T) {
  return class AudioRFB extends Base {
    onAudio: ((e: AudioEvent) => void) | null = null;
    audioAcked = false;

    /** Asks QEMU to send sound (after it acknowledged the extension). */
    setAudio(on: boolean) {
      const sock = (this as any)._sock;
      if (!sock || !this.audioAcked) return false;
      const msg = on ? audioOnMessages() : audioOffMessage();
      sock.sQpushBytes(msg);
      sock.flush();
      return true;
    }

    _sendEncodings() {
      const messages = (Base as any).messages;
      const orig = messages.clientEncodings;
      messages.clientEncodings = (sock: unknown, encs: number[]) => orig(sock, [...encs, QEMU_AUDIO_ENCODING]);
      try {
        (super._sendEncodings as () => void)();
      } finally {
        messages.clientEncodings = orig;
      }
    }

    _handleRect() {
      if ((this as any)._FBU.encoding === QEMU_AUDIO_ENCODING) {
        this.audioAcked = true; // QEMU's empty acknowledgement
        return true;
      }
      return (super._handleRect as () => boolean)();
    }

    _normalMsg() {
      const self = this as any;
      const sock = self._sock;
      if (self._FBU.rects === 0 && sock.rQlen() >= 1 && sock.rQpeek8() === 255) {
        const r = parseAudio(sock.rQpeekBytes(Math.min(sock.rQlen(), 8 + MAX_AUDIO_CHUNK), false));
        if ("error" in r) {
          self._fail(r.error);
          return true;
        }
        if (r.need) return false;
        sock.rQskipBytes(r.consumed);
        this.onAudio?.(r.event);
        return true;
      }
      return (super._normalMsg as () => boolean)();
    }
  };
}
