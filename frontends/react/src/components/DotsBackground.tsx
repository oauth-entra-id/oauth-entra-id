import { useId } from 'react';

export function DotsBackground() {
  const id = useId();

  return (
    <svg
      aria-hidden="true"
      className="pointer-events-none absolute inset-0 size-full fill-neutral-400/80 [mask-image:radial-gradient(350px_circle_at_center,white,transparent)] md:[mask-image:radial-gradient(450px_circle_at_center,white,transparent)] lg:[mask-image:radial-gradient(550px_circle_at_center,white,transparent)]">
      <defs>
        <pattern
          x={0}
          y={0}
          width={16}
          height={16}
          id={id}
          patternContentUnits="userSpaceOnUse"
          patternUnits="userSpaceOnUse">
          <circle cx={1} cy={1} r={1} id="pattern-circle" />
        </pattern>
      </defs>
      <rect fill={`url(#${id})`} height="100%" width="100%" strokeWidth={0} />
    </svg>
  );
}
