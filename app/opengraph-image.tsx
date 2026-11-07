import { OG_CONTENT_TYPE, OG_SIZE, ogCard } from './lib/ogCard';
import { BRAND } from './lib/seo';

export const alt = BRAND;
export const size = OG_SIZE;
export const contentType = OG_CONTENT_TYPE;

export default function OpengraphImage() {
  return ogCard({
    kicker: 'Industrial Autonomous Assurance',
    title: 'Does the safety evidence still describe the machine? Know on the day it stops.',
  });
}
