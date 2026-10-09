import assert from 'node:assert/strict'
import { randomBytes } from 'node:crypto'
import { describe, it } from 'node:test'
import { constants, deflateSync } from 'node:zlib'
import { inflateZlibAt } from './zlib-inflate.ts'

function samples() {
	const text = Buffer.from('export default async function main() { return "hello kody" }\n'.repeat(500))
	return [
		Buffer.alloc(0),
		Buffer.from('a'),
		text,
		randomBytes(70_000), // incompressible → stored blocks
		Buffer.alloc(300_000, 'x'), // long back-references
		Buffer.concat([text, randomBytes(5000), text]),
	]
}

const options = [
	{ level: 0 },
	{ level: 1 },
	{ level: 6 },
	{ level: 9 },
	{ level: 6, strategy: constants.Z_FIXED },
	{ level: 6, strategy: constants.Z_HUFFMAN_ONLY },
	{ level: 6, strategy: constants.Z_RLE },
]

describe('inflateZlibAt', () => {
	it('matches node:zlib for every block type and reports consumed bytes', () => {
		for (const data of samples()) {
			for (const opt of options) {
				const compressed = deflateSync(data, opt)
				const r = inflateZlibAt(compressed, 0)
				assert.deepEqual(Buffer.from(r.output), data)
				assert.equal(r.bytesRead, compressed.length)
			}
		}
	})

	it('walks back-to-back streams like a git packfile', () => {
		const parts = samples().map((d, i) => deflateSync(d, options[i % options.length]!))
		const header = Buffer.from('PACK\0\0\0\x02junk')
		const pack = Buffer.concat([header, ...parts, Buffer.from('trailer-sha')])
		let offset = header.length
		for (const [i, data] of samples().entries()) {
			const r = inflateZlibAt(pack, offset)
			assert.equal(r.output.byteLength, data.length, `object ${i}`)
			assert.equal(r.bytesRead, parts[i]!.length, `object ${i}`)
			offset += r.bytesRead
		}
		assert.equal(pack.subarray(offset).toString(), 'trailer-sha')
	})

	it('rejects truncated and corrupted input', () => {
		const compressed = deflateSync(Buffer.from('hello hello hello hello'))
		assert.throws(() => inflateZlibAt(compressed.subarray(0, compressed.length - 2), 0), /Corrupt git pack/)
		const bad = Buffer.from(compressed)
		bad[bad.length - 1] = bad[bad.length - 1]! ^ 0xff
		assert.throws(() => inflateZlibAt(bad, 0), /adler32/)
	})
})
