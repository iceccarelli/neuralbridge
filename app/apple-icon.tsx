import { iconImage } from './lib/ogCard';

// 180x180, opaque: iOS applies its own rounding and shows transparency as black.
export const size = { width: 180, height: 180 };
export const contentType = 'image/png';

export default function AppleIcon() {
  return iconImage(180, true);
}
