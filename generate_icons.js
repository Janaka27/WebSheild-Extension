const fs = require('fs');
const path = require('path');
const zlib = require('zlib');

function crc32(buf) {
  let crc = -1;
  for (let i = 0; i < buf.length; i++) {
    let c = (crc ^ buf[i]) & 0xff;
    for (let j = 0; j < 8; j++) {
      c = (c & 1) ? (0xedb88320 ^ (c >>> 1)) : (c >>> 1);
    }
    crc = (crc >>> 8) ^ c;
  }
  return (crc ^ -1) >>> 0;
}

function createChunk(type, data) {
  const len = Buffer.alloc(4);
  len.writeUInt32BE(data.length, 0);
  const typeBuf = Buffer.from(type, 'ascii');
  const crcBuf = Buffer.alloc(4);
  const checksum = crc32(Buffer.concat([typeBuf, data]));
  crcBuf.writeUInt32BE(checksum, 0);
  return Buffer.concat([len, typeBuf, data, crcBuf]);
}

function generatePng(width, height, drawFn) {
  const signature = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);

  // IHDR
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(width, 0);
  ihdr.writeUInt32BE(height, 4);
  ihdr[8] = 8;  // bit depth
  ihdr[9] = 6;  // color type RGBA
  ihdr[10] = 0; // compression
  ihdr[11] = 0; // filter
  ihdr[12] = 0; // interlace
  const ihdrChunk = createChunk('IHDR', ihdr);

  // Raw pixel data: width * 4 + 1 (filter byte) per row
  const rawRows = [];
  for (let y = 0; y < height; y++) {
    const row = Buffer.alloc(width * 4 + 1);
    row[0] = 0; // Filter type None
    for (let x = 0; x < width; x++) {
      const [r, g, b, a] = drawFn(x, y, width, height);
      const offset = 1 + x * 4;
      row[offset] = r;
      row[offset + 1] = g;
      row[offset + 2] = b;
      row[offset + 3] = a;
    }
    rawRows.push(row);
  }

  const idatData = zlib.deflateSync(Buffer.concat(rawRows));
  const idatChunk = createChunk('IDAT', idatData);

  // IEND
  const iendChunk = createChunk('IEND', Buffer.alloc(0));

  return Buffer.concat([signature, ihdrChunk, idatChunk, iendChunk]);
}

function shieldPainter(x, y, w, h) {
  const nx = (x / w) * 2 - 1;
  const ny = (y / h) * 2 - 1;

  // Background circle / rounded square: sleek cyan to blue gradient
  const dist = Math.sqrt(nx * nx + ny * ny);
  if (dist > 0.95) return [0, 0, 0, 0]; // Transparent padding

  // Shield outline logic
  // Shield shape: upper part rectangle top, curve down to bottom center
  const shieldWidth = 0.55;
  const isInsideShieldTop = Math.abs(nx) <= shieldWidth && ny >= -0.65 && ny <= 0.1;
  const isInsideShieldBottom = Math.abs(nx) <= shieldWidth * (1 - (ny - 0.1) / 0.7) && ny > 0.1 && ny <= 0.8;

  const inShield = isInsideShieldTop || isInsideShieldBottom;

  // Outer background gradient: Dark Navy to Purple #0f172a -> #1e1b4b
  let r = Math.floor(15 + (1 - ny) * 15);
  let g = Math.floor(23 + (1 - ny) * 20);
  let b = Math.floor(42 + (1 - ny) * 60);
  let a = 255;

  if (inShield) {
    // Shield color: Vibrant Cyan/Emerald `#00f2fe` -> `#4facfe`
    const shieldGrad = (ny + 0.65) / 1.45;
    r = Math.floor(0 + shieldGrad * 79);
    g = Math.floor(242 - shieldGrad * 70);
    b = Math.floor(254);

    // Checkmark inside shield
    const cx = nx;
    const cy = ny - 0.05;
    const check1 = (cy - 0.2 * cx >= -0.08 && cy - 0.2 * cx <= 0.12) && (cx >= -0.3 && cx <= 0.0);
    const check2 = (cy + cx >= -0.1 && cy + cx <= 0.1) && (cx >= -0.05 && cx <= 0.35);
    if (check1 || check2) {
      r = 255; g = 255; b = 255; // White checkmark
    }
  }

  return [r, g, b, a];
}

const iconsDir = path.join(__dirname, 'icons');
if (!fs.existsSync(iconsDir)) {
  fs.mkdirSync(iconsDir, { recursive: true });
}

[16, 48, 128].forEach(size => {
  const pngBuf = generatePng(size, size, shieldPainter);
  fs.writeFileSync(path.join(iconsDir, `icon-${size}.png`), pngBuf);
  console.log(`Generated icon-${size}.png (${pngBuf.length} bytes)`);
});
