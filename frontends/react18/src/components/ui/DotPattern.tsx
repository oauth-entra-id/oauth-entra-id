/* eslint-disable @typescript-eslint/no-explicit-any */
import { useId } from 'react';
import { cn } from '~/lib/utils';

interface DotPatternProps {
  // biome-ignore lint/suspicious/noExplicitAny: Outside of our control
  width?: any;
  // biome-ignore lint/suspicious/noExplicitAny: Outside of our control
  height?: any;
  // biome-ignore lint/suspicious/noExplicitAny: Outside of our control
  x?: any;
  // biome-ignore lint/suspicious/noExplicitAny: Outside of our control
  y?: any;
  // biome-ignore lint/suspicious/noExplicitAny: Outside of our control
  cx?: any;
  // biome-ignore lint/suspicious/noExplicitAny: Outside of our control
  cy?: any;
  // biome-ignore lint/suspicious/noExplicitAny: Outside of our control
  cr?: any;
  className?: string;
  // biome-ignore lint/suspicious/noExplicitAny: Outside of our control
  [key: string]: any;
}
export function DotPattern({
  width = 16,
  height = 16,
  x = 0,
  y = 0,
  cx = 1,
  cy = 1,
  cr = 1,
  className,
  ...props
}: DotPatternProps) {
  const id = useId();

  return (
    <svg
      aria-hidden="true"
      className={cn('pointer-events-none absolute inset-0 h-full w-full fill-neutral-400/80', className)}
      {...props}>
      <defs>
        <pattern
          height={height}
          id={id}
          patternContentUnits="userSpaceOnUse"
          patternUnits="userSpaceOnUse"
          width={width}
          x={x}
          y={y}>
          <circle cx={cx} cy={cy} id="pattern-circle" r={cr} />
        </pattern>
      </defs>
      <rect fill={`url(#${id})`} height="100%" strokeWidth={0} width="100%" />
    </svg>
  );
}

export default DotPattern;
