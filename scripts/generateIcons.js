import fs from 'fs';
import path from 'path';

// 1x1 or base64 transparent/blue shield PNG fallback
// Simple valid 16x16, 48x48, 128x128 PNG buffer generator
const png16Base64 = "iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAAAWElEQVR42mNkQAO8DJjA4z4z/8eNlBhgA4ZkY/7/nxm7hF4bGBg+gWkYBv5n/L/vHzp/XAZghP///w+k8XkBHvP/4zF8mhkb3iOaEUAOAx6wX008wGgqHwUAAB18X6s9lW+lAAAAAElFTkSuQmCC";
const png48Base64 = "iVBORw0KGgoAAAANSUhEUgAAADAAAAAwCAYAAABXAvmHAAAAbklEQVR42u3XwQmAMAyA4Tgtp7s4hNvhKG6iG9lAKKj10T54D9pCSL70g2ZkZmbm10hI7d1d23s77z9X78sZgAJQAApAASgABaAAFIACUAAKQAEoAAWgABSAYt/gqQJ14dO3kG/0268mUAAKQAEoAAV873oBt7sB63V26+kAAAAASUVORK5CYII=";
const png128Base64 = "iVBORw0KGgoAAAANSUhEUgAAAIAAAACACAYAAADDPmHLAAAAgklEQVR42u3XQQ0AIAwEsfNvdg+4sQZUkqZ74LpP8DczM7M6aYkL8BAAAQRAAAQQAAEEQAAEEEAABBAAAQRAAAQQAAEEQAAEEEAABBAAAQRAAAQQAAEEQAAEEEAABBAAAQRAAAQQAAEEQAAEEEAABBAAAQRAAAQQAAEEQAAEEEAABFw4jYADqB8y8QAAAABJRU5ErkJggg==";

const targets = [
  './public/extension/icons',
  './extension/icons'
];

targets.forEach(dir => {
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, 'icon16.png'), Buffer.from(png16Base64, 'base64'));
  fs.writeFileSync(path.join(dir, 'icon48.png'), Buffer.from(png48Base64, 'base64'));
  fs.writeFileSync(path.join(dir, 'icon128.png'), Buffer.from(png128Base64, 'base64'));
});

console.log('Icons generated successfully.');
