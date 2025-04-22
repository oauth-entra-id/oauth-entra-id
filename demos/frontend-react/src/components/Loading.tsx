import { LoaderCircle } from 'lucide-react';
import { useThemeStore } from '~/stores/themeStore';

export function Loading() {
  const theme = useThemeStore((state) => state.theme);
  return (
    <div
      className={`fixed inset-0 z-50 flex flex-col items-center justify-center bg-background text-foreground ${theme}`}>
      <LoaderCircle className="animate-spin text-4xl text-primary mb-4" />
      <div className="text-2xl font-semibold">Please wait...</div>
      <div className="text-sm text-muted-foreground mt-2">Loading, this might take a few seconds.</div>
    </div>
  );
}
