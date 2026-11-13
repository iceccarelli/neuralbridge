import { getVisual } from '../lib/visuals';
import { jsonLdString } from '../lib/seo';

interface VisualDiagramProps {
  slug: string;
  variant?: 'light' | 'dark';
  className?: string;
}

export default function VisualDiagram({ slug, variant = 'light', className = '' }: VisualDiagramProps) {
  const v = getVisual(slug);
  const ld = { '@context': 'https://schema.org', ...v.schemaOrgImageObject };

  return (
    <figure className={`visual-figure ${variant === 'dark' ? 'visual-figure-dark' : ''} ${className}`.trim()}>
      <script type="application/ld+json" dangerouslySetInnerHTML={{ __html: jsonLdString(ld) }} />
      <div className="visual-frame">
        <picture>
          <source srcSet={v.webpPath} type="image/webp" />
          <img
            src={v.pngPath}
            alt={v.alt}
            width={v.width}
            height={v.height}
            loading="lazy"
            decoding="async"
          />
        </picture>
      </div>
      <figcaption className="visual-caption">
        <div className="visual-caption-head">
          <strong>{v.caption}</strong>
          <code>{v.cliOrApiReference}</code>
        </div>
        <p>{v.aeoSummary}</p>
      </figcaption>
    </figure>
  );
}
