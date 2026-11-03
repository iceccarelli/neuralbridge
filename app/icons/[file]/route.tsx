import { iconImage } from '../../lib/ogCard';

// The PNG icons the web manifest and the Organization logo point at, generated from the same mark as
// app/icon.svg. Static: rendered once at build time. The set is closed; any other name is a 404.
export const dynamic = 'force-static';
export const dynamicParams = false;

const ICONS: Record<string, { px: number; maskable: boolean }> = {
  'icon-48.png': { px: 48, maskable: false },
  'icon-192.png': { px: 192, maskable: false },
  'icon-512.png': { px: 512, maskable: false },
  'icon-maskable-512.png': { px: 512, maskable: true },
};

export function generateStaticParams() {
  return Object.keys(ICONS).map((file) => ({ file }));
}

export async function GET(_req: Request, { params }: { params: Promise<{ file: string }> }) {
  const { file } = await params;
  const icon = ICONS[file];
  if (!icon) return new Response('Not found', { status: 404 });
  return iconImage(icon.px, icon.maskable);
}
