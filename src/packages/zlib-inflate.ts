import { KodyError } from '../lib/errors.ts'

/**
 * Pure-JS zlib (RFC 1950) + DEFLATE (RFC 1951) decoder that reports how many
 * input bytes the stream consumed.
 *
 * Git packfiles concatenate zlib streams with no length prefix, so the parser
 * must know where each one ends. `node:zlib`'s `inflateSync(…, { info: true })`
 * exposes that via `engine.bytesWritten` on Node, but Deno's node-compat
 * zlib ignores `info` and returns a bare Buffer (→ "Cannot read properties of
 * undefined (reading 'bytesWritten')"). This decoder has no runtime
 * dependency, so it behaves the same on Node, Deno celld and workerd.
 */

const LENGTH_BASE = [
	3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258,
]
const LENGTH_EXTRA = [0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0]
const DIST_BASE = [
	1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145,
	8193, 12289, 16385, 24577,
]
const DIST_EXTRA = [0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13]
const CODE_LENGTH_ORDER = [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15]

type Huffman = { counts: Uint16Array; symbols: Uint16Array }

function corrupt(message: string): never {
	throw new KodyError('invalid_package', `Corrupt git pack: ${message}.`, { status: 502 })
}

function buildHuffman(lengths: ArrayLike<number>): Huffman {
	const counts = new Uint16Array(16)
	for (let i = 0; i < lengths.length; i += 1) counts[lengths[i]!]! += 1
	counts[0] = 0
	const offsets = new Uint16Array(16)
	for (let len = 1; len < 16; len += 1) offsets[len] = offsets[len - 1]! + counts[len - 1]!
	const symbols = new Uint16Array(lengths.length)
	for (let sym = 0; sym < lengths.length; sym += 1) {
		const len = lengths[sym]!
		if (len !== 0) symbols[offsets[len]!++] = sym
	}
	return { counts, symbols }
}

const FIXED_LIT = buildHuffman(Array.from({ length: 288 }, (_, i) => (i < 144 ? 8 : i < 256 ? 9 : i < 280 ? 7 : 8)))
const FIXED_DIST = buildHuffman(Array.from({ length: 30 }, () => 5))

class Output {
	buf = new Uint8Array(1024)
	len = 0
	ensure(extra: number) {
		if (this.len + extra <= this.buf.length) return
		let size = this.buf.length * 2
		while (size < this.len + extra) size *= 2
		const next = new Uint8Array(size)
		next.set(this.buf.subarray(0, this.len))
		this.buf = next
	}
	push(byte: number) {
		this.ensure(1)
		this.buf[this.len++] = byte
	}
}

/**
 * Inflate one zlib stream starting at `offset`. Returns the decompressed bytes
 * and how many input bytes (header + deflate data + adler32 trailer) it used.
 */
export function inflateZlibAt(input: Uint8Array, offset: number): { output: Uint8Array; bytesRead: number } {
	let pos = offset
	let bitBuf = 0
	let bitCnt = 0

	const bits = (need: number) => {
		while (bitCnt < need) {
			if (pos >= input.length) corrupt('unexpected end of zlib stream')
			bitBuf |= input[pos++]! << bitCnt
			bitCnt += 8
		}
		const value = bitBuf & ((1 << need) - 1)
		bitBuf >>>= need
		bitCnt -= need
		return value
	}

	const decode = (h: Huffman) => {
		let code = 0
		let first = 0
		let index = 0
		for (let len = 1; len < 16; len += 1) {
			code |= bits(1)
			const count = h.counts[len]!
			if (code - count < first) return h.symbols[index + (code - first)]!
			index += count
			first += count
			first <<= 1
			code <<= 1
		}
		return corrupt('bad huffman code')
	}

	if (input.length - pos < 2) corrupt('missing zlib header')
	const cmf = input[pos]!
	const flg = input[pos + 1]!
	if ((cmf & 0x0f) !== 8 || ((cmf << 8) | flg) % 31 !== 0) corrupt('bad zlib header')
	if (flg & 0x20) corrupt('preset dictionary not supported')
	pos += 2

	const out = new Output()
	let last = 0
	do {
		last = bits(1)
		const type = bits(2)
		if (type === 0) {
			bitBuf = 0
			bitCnt = 0
			if (pos + 4 > input.length) corrupt('truncated stored block')
			const len = input[pos]! | (input[pos + 1]! << 8)
			const nlen = input[pos + 2]! | (input[pos + 3]! << 8)
			if ((len ^ 0xffff) !== nlen) corrupt('stored block length mismatch')
			pos += 4
			if (pos + len > input.length) corrupt('truncated stored block')
			out.ensure(len)
			out.buf.set(input.subarray(pos, pos + len), out.len)
			out.len += len
			pos += len
			continue
		}
		let lit: Huffman
		let dist: Huffman
		if (type === 1) {
			lit = FIXED_LIT
			dist = FIXED_DIST
		} else if (type === 2) {
			const hlit = bits(5) + 257
			const hdist = bits(5) + 1
			const hclen = bits(4) + 4
			const clLengths = new Uint8Array(19)
			for (let i = 0; i < hclen; i += 1) clLengths[CODE_LENGTH_ORDER[i]!] = bits(3)
			const cl = buildHuffman(clLengths)
			const lengths = new Uint8Array(hlit + hdist)
			for (let i = 0; i < hlit + hdist;) {
				const sym = decode(cl)
				if (sym < 16) lengths[i++] = sym
				else {
					let repeat = 0
					let value = 0
					if (sym === 16) {
						if (i === 0) corrupt('repeat with no previous length')
						value = lengths[i - 1]!
						repeat = 3 + bits(2)
					} else if (sym === 17) repeat = 3 + bits(3)
					else repeat = 11 + bits(7)
					if (i + repeat > hlit + hdist) corrupt('too many code lengths')
					while (repeat-- > 0) lengths[i++] = value
				}
			}
			lit = buildHuffman(lengths.subarray(0, hlit))
			dist = buildHuffman(lengths.subarray(hlit))
		} else {
			return corrupt('invalid block type')
		}
		for (;;) {
			const sym = decode(lit)
			if (sym < 256) out.push(sym)
			else if (sym === 256) break
			else {
				const li = sym - 257
				if (li >= 29) corrupt('bad length symbol')
				const length = LENGTH_BASE[li]! + bits(LENGTH_EXTRA[li]!)
				const di = decode(dist)
				if (di >= 30) corrupt('bad distance symbol')
				const distance = DIST_BASE[di]! + bits(DIST_EXTRA[di]!)
				if (distance > out.len) corrupt('distance too far back')
				out.ensure(length)
				const b = out.buf
				let from = out.len - distance
				for (let k = 0; k < length; k += 1) b[out.len++] = b[from++]!
			}
		}
	} while (!last)

	// Unused whole bytes left in the bit buffer belong to the next object.
	pos -= bitCnt >>> 3
	if (pos + 4 > input.length) corrupt('missing adler32')
	const output = out.buf.slice(0, out.len)
	const expected = ((input[pos]! << 24) | (input[pos + 1]! << 16) | (input[pos + 2]! << 8) | input[pos + 3]!) >>> 0
	let a = 1
	let b = 0
	for (let i = 0; i < output.length; i += 1) {
		a = (a + output[i]!) % 65521
		b = (b + a) % 65521
	}
	if (((b << 16) | a) >>> 0 !== expected) corrupt('adler32 mismatch')
	pos += 4
	return { output, bytesRead: pos - offset }
}
