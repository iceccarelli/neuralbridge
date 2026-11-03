import { OG_CONTENT_TYPE, OG_SIZE, ogCard } from './lib/ogCard';
import { BRAND } from './lib/seo';

export const alt = BRAND;
export const size = OG_SIZE;
export const contentType = OG_CONTENT_TYPE;

export default function OpengraphImage() {
  return ogCard({
    kicker: 'Evidence infrastructure for CRA Art. 14 and Machinery Reg. 2023/1230',
    title: 'A hash-chained record of what is on each machine, which checks were run against it, and when.',
  });
}
