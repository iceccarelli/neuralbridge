'use client';

import Image from 'next/image';
import { useEffect, useRef, useState } from 'react';
import type { ImageSlot } from '../lib/images';

interface RotatingImageProps {
  slot: ImageSlot;
  /** CSS aspect-ratio, e.g. '16/9', '4/3', '4/5'. */
  aspect?: string;
  /** Only ever true for the single LCP-critical hero image on a page. */
  priority?: boolean;
  sizes?: string;
  /** How long each frame holds before crossfading to the other. 8-12s per DESIGN.md. */
  intervalMs?: number;
  /** Stagger the first flip so a grid of cards doesn't flash in sync. */
  offsetMs?: number;
  className?: string;
  /** Small dot indicators — hero only, never on card grids (noisy). */
  dots?: boolean;
}

const DEFAULT_INTERVAL_MS = 10000;

export default function RotatingImage({
  slot,
  aspect = '4/3',
  priority = false,
  sizes = '(max-width: 768px) 100vw, 50vw',
  intervalMs = DEFAULT_INTERVAL_MS,
  offsetMs = 0,
  className = '',
  dots = false,
}: RotatingImageProps) {
  const hasB = Boolean(slot.b);
  const [showB, setShowB] = useState(false);
  const [reducedMotion, setReducedMotion] = useState(false);
  // The alternate frame is not in the page until just before its first use, so a visitor who leaves, or who
  // prefers reduced motion (and so never sees it), never downloads it. Rendering it from the start made
  // roughly 40% of the home page's image bytes frames that sit at opacity 0.
  const [armed, setArmed] = useState(false);
  const bLoaded = useRef(false);
  const timeoutRef = useRef<number>();

  useEffect(() => {
    const mq = window.matchMedia('(prefers-reduced-motion: reduce)');
    setReducedMotion(mq.matches);
    const onChange = () => setReducedMotion(mq.matches);
    mq.addEventListener('change', onChange);
    return () => mq.removeEventListener('change', onChange);
  }, []);

  useEffect(() => {
    if (!hasB || reducedMotion) return;

    // Only flip to B once it has loaded; flipping back to A is always allowed.
    const tick = () => {
      if (document.visibilityState === 'visible') setShowB((v) => (v ? false : bLoaded.current));
      timeoutRef.current = window.setTimeout(tick, intervalMs);
    };
    const armTimer = window.setTimeout(() => setArmed(true), Math.max(0, intervalMs + offsetMs - 2000));
    timeoutRef.current = window.setTimeout(tick, intervalMs + offsetMs);

    return () => {
      window.clearTimeout(armTimer);
      window.clearTimeout(timeoutRef.current);
    };
  }, [hasB, reducedMotion, intervalMs, offsetMs]);

  if (!hasB) {
    return (
      <div className={`media-band ${className}`} style={{ aspectRatio: aspect }}>
        <Image src={slot.a.src} alt={slot.a.alt} fill sizes={sizes} priority={priority} fetchPriority={priority ? 'high' : undefined} style={{ objectFit: 'cover' }} />
      </div>
    );
  }

  return (
    <div className={`media-band ${className}`} style={{ aspectRatio: aspect }}>
      <Image
        src={slot.a.src}
        alt={showB ? '' : slot.a.alt}
        aria-hidden={showB}
        fill
        sizes={sizes}
        priority={priority}
        fetchPriority={priority ? 'high' : undefined}
        style={{ objectFit: 'cover', opacity: showB ? 0 : 1, transition: 'opacity var(--duration-panel) var(--ease)' }}
      />
      {armed && !reducedMotion && (
        <Image
          src={slot.b!.src}
          alt={showB ? slot.b!.alt : ''}
          aria-hidden={!showB}
          fill
          sizes={sizes}
          onLoad={() => {
            bLoaded.current = true;
          }}
          style={{ objectFit: 'cover', opacity: showB ? 1 : 0, transition: 'opacity var(--duration-panel) var(--ease)' }}
        />
      )}
      {dots && (
        <div className="media-dots" aria-hidden="true">
          <span className={`media-dot ${!showB ? 'is-active' : ''}`} />
          <span className={`media-dot ${showB ? 'is-active' : ''}`} />
        </div>
      )}
    </div>
  );
}
