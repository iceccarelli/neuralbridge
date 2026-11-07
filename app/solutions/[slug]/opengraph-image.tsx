import { OG_CONTENT_TYPE, OG_SIZE, clip, ogCard } from '../../lib/ogCard';
import { SOLUTIONS, getSolution } from '../../lib/solutions';

export const size = OG_SIZE;
export const contentType = OG_CONTENT_TYPE;
export const alt = 'Industrial Autonomous Assurance solution page';
export const dynamicParams = false;

export function generateStaticParams() {
  return SOLUTIONS.map((s) => ({ slug: s.slug }));
}

export default async function Image({ params }: { params: Promise<{ slug: string }> }) {
  const { slug } = await params;
  const solution = getSolution(slug);
  return ogCard({
    kicker: solution ? `For: ${solution.role}` : 'Solutions',
    title: clip(solution ? solution.headline : 'NeuralBridge Industrial Autonomous Assurance', 110),
  });
}
