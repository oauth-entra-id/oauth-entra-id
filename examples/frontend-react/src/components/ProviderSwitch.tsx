import { cn } from '~/lib/utils';
import { type Provider, useProviderStore } from '~/stores/provider-store';
import { ToggleGroup, ToggleGroupItem } from './ui/ToggleGroup';

const providers: Array<{ value: Provider; label: string }> = [
  { value: 'oauth', label: 'OAuthProvider' },
  { value: 'lite', label: 'LiteProvider' },
];

/** Chooses what the demo shows: the full OAuthProvider or the LiteProvider. */
export function ProviderSwitch() {
  const provider = useProviderStore((state) => state.provider);
  const setProvider = useProviderStore((state) => state.setProvider);

  return (
    <ToggleGroup
      type="single"
      size="sm"
      aria-label="Provider"
      className="gap-0 border-[1.5px] rounded-lg bg-background"
      value={provider}
      onValueChange={(value) => value && setProvider(value as Provider)}>
      {providers.map(({ value, label }) => (
        <ToggleGroupItem
          key={value}
          value={value}
          aria-label={label}
          size="sm"
          className={cn(
            'text-xs sm:text-sm font-semibold',
            provider === value && 'data-[state=on]:bg-primary data-[state=on]:text-primary-foreground',
          )}>
          {label}
        </ToggleGroupItem>
      ))}
    </ToggleGroup>
  );
}
