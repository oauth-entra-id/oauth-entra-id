import { Moon, Sun } from 'lucide-react';
import { Button } from '~/components/ui/Button';
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from '~/components/ui/DropdownMenu';
import { useDevTools } from '~/hooks/useDevTools';
import { useToggle } from '~/hooks/useToggle';
import { useThemeStore } from '~/stores/themeStore';

export function Navbar() {
  const [inspectDisabled, toggleInspectDisabled] = useToggle(true);
  useDevTools(inspectDisabled);

  return (
    <nav className="w-full flex flex-row items-center justify-between px-4 py-2">
      <div
        className="font-mono font-black text-xl tracking-wide bg-gradient-to-br from-foreground to-50% to-muted-foreground bg-clip-text text-transparent"
        onDoubleClick={() => {
          toggleInspectDisabled();
        }}>
        Demo
      </div>
      <ModeToggle />
    </nav>
  );
}

function ModeToggle() {
  const { setTheme } = useThemeStore();

  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button size="icon" variant="outline">
          <Sun className="h-[1.2rem] w-[1.2rem] rotate-0 scale-100 transition-all dark:-rotate-90 dark:scale-0" />
          <Moon className="absolute h-[1.2rem] w-[1.2rem] rotate-90 scale-0 transition-all dark:rotate-0 dark:scale-100" />
          <span className="sr-only">Toggle theme</span>
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end">
        <DropdownMenuItem
          onClick={() => {
            setTheme('light');
          }}>
          Light
        </DropdownMenuItem>
        <DropdownMenuItem
          onClick={() => {
            setTheme('dark');
          }}>
          Dark
        </DropdownMenuItem>
        <DropdownMenuItem
          onClick={() => {
            setTheme('system');
          }}>
          System
        </DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  );
}
