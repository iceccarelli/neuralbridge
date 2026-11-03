import { OG_CONTENT_TYPE, OG_SIZE, clip, ogCard } from '../../lib/ogCard';
import { PRODUCT_PAGES, getProductPage } from '../../lib/productPages';

export const size = OG_SIZE;
export const contentType = OG_CONTENT_TYPE;
export const alt = 'Industrial Autonomous Assurance product page';
export const dynamicParams = false;

export function generateStaticParams() {
  return PRODUCT_PAGES.map((p) => ({ slug: p.slug }));
}

export default async function Image({ params }: { params: Promise<{ slug: string }> }) {
  const { slug } = await params;
  const page = getProductPage(slug);
  return ogCard({
    kicker: page ? page.kicker : 'How it works',
    title: clip(page ? page.h1 : 'Industrial Autonomous Assurance', 110),
  });
}
