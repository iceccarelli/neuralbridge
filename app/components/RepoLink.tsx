import type { ReactNode } from 'react';
import { repoLink } from '../lib/links';

/**
 * A link into the source repository, rendered only when the repo is public (lib/links.ts REPO_PUBLIC).
 * With the repo private it renders nothing, or, with `plain`, the children as unlinked text so a
 * sentence that names a file still reads naturally.
 */
export default function RepoLink({
  path,
  children,
  plain = false,
  className,
  onClick,
}: {
  path: string;
  children: ReactNode;
  plain?: boolean;
  className?: string;
  onClick?: () => void;
}) {
  const href = repoLink(path);
  if (!href) return plain ? <>{children}</> : null;
  return (
    <a className={className} href={href} target="_blank" rel="noreferrer" onClick={onClick}>
      {children}
    </a>
  );
}
