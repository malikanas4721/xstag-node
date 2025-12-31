const Jimp = require('jimp');

async function readImageFromPath(path) { return await Jimp.read(path); }
async function writeImageToBuffer(image) { return await image.getBufferAsync(Jimp.MIME_PNG); }

function embedPayload(image, payload) {
  const bits = payload.split('').map(c => c.charCodeAt(0).toString(2).padStart(8, '0')).join('');
  const width = image.bitmap.width, height = image.bitmap.height;
  const capacity = width * height * 3;
  if (bits.length > capacity) throw new Error('Image too small for payload.');
  let i = 0;
  image.scan(0, 0, width, height, function (x, y, offset) {
    for (let ch = 0; ch < 3 && i < bits.length; ch++) {
      const orig = this.bitmap.data[offset + ch];
      const bit = Number(bits[i]);
      this.bitmap.data[offset + ch] = (orig & ~1) | bit;
      i++;
    }
  });
  return image;
}

function extractPayload(image) {
  const width = image.bitmap.width, height = image.bitmap.height;
  const bits = [];
  image.scan(0, 0, width, height, function (x, y, offset) {
    bits.push((this.bitmap.data[offset] & 1).toString());
    bits.push((this.bitmap.data[offset+1] & 1).toString());
    bits.push((this.bitmap.data[offset+2] & 1).toString());
  });
  const chars = [];
  for (let i = 0; i < bits.length; i += 8) {
    const byte = bits.slice(i, i+8);
    if (byte.length < 8) break;
    chars.push(String.fromCharCode(parseInt(byte.join(''), 2)));
  }
  return chars.join('');
}

module.exports = { readImageFromPath, writeImageToBuffer, embedPayload, extractPayload };
