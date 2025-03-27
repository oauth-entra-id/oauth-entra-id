import React from 'react';
import { cn } from '~/lib/utils';

export function MicrosoftSVG({ className, ...props }: React.SVGProps<SVGSVGElement>) {
  return (
    <svg
      className={cn('aspect-square w-6', className)}
      fill="none"
      viewBox="0 0 16 16"
      xmlns="http://www.w3.org/2000/svg"
      {...props}>
      <g strokeWidth="0" />
      <g strokeLinecap="round" strokeLinejoin="round" />
      <g>
        <path d="M1 1h6.5v6.5H1V1z" fill="#F35325" />
        <path d="M8.5 1H15v6.5H8.5V1z" fill="#81BC06" />
        <path d="M1 8.5h6.5V15H1V8.5z" fill="#05A6F0" />
        <path d="M8.5 8.5H15V15H8.5V8.5z" fill="#FFBA08" />
      </g>
    </svg>
  );
}
