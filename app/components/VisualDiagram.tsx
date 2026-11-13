import { getVisual } from '../lib/visuals';
import { jsonLdString } from '../lib/seo';

interface VisualDiagramProps {
  slug: string;
  variant?: 'light' | 'dark';
  emitJsonLd?: boolean;
  showCaption?: boolean;
  className?: string;
}

export default function VisualDiagram({
  slug,
  variant = 'light',
  emitJsonLd = true,
  showCaption = true,
  className = '',
}: VisualDiagramProps) {
  const v = getVisual(slug);
  const ld = { '@context': 'https://schema.org', ...v.schemaOrgImageObject };

  return (
    <figure className={`visual-figure ${variant === 'dark' ? 'visual-figure-dark' : ''} ${className}`.trim()}>
      {emitJsonLd ? (
        <script type="application/ld+json" dangerouslySetInnerHTML={{ __html: jsonLdString(ld) }} />
      ) : null}
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
      {showCaption ? (
        <figcaption className="visual-caption">
          <div className="visual-caption-head">
            <strong>{v.caption}</strong>
            {v.cliOrApiReference ? <code>{v.cliOrApiReference}</code> : null}
          </div>
          {v.aeoSummary ? <p>{v.aeoSummary}</p> : null}
        </figcaption>
      ) : null}
    </figure>
  );
}
