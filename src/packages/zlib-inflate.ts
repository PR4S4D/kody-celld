import { Inflate, Z_BUF_ERROR, type ZStream } from 'pako'
import { KodyError } from '../lib/errors.ts'

/**
 * Inflate one zlib (RFC 1950) stream starting at `offset` and report how many
 * input bytes it consumed (header + deflate data + adler32 trailer).
 *
 * Git packfiles concatenate zlib streams with no length prefix, so the parser
 * must know where each one ends. `node:zlib`'s `inflateSync(…, { info: true })`
 * exposes that via `engine.bytesWritten` on Node, but celld's node-compat zlib
 * ignores `info`. pako's streaming `Inflate` stops at the end of the stream and
 * leaves the unread tail in `strm.avail_in` on every runtime.
 */
export function inflateZlibAt(input: Uint8Array, offset: number): { output: Uint8Array; bytesRead: number } {
	const rest = input.subarray(offset)
	// Explicit windowBits keeps pako on zlib only (no gzip autodetect).
	const inflate = new Inflate({ windowBits: 15 })
	let strm: ZStream | undefined
	inflate.onStart = (s) => {
		strm = s
	}
	inflate.push(rest, true)
	if (inflate.err !== 0 || !strm) {
		const reason =
			inflate.err === Z_BUF_ERROR
				? 'unexpected end of zlib stream'
				: inflate.msg === 'incorrect data check'
					? 'adler32 mismatch'
					: inflate.msg
		throw new KodyError('invalid_package', `Corrupt git pack: ${reason}.`, { status: 502 })
	}
	return { output: inflate.result, bytesRead: rest.byteLength - strm.avail_in }
}
