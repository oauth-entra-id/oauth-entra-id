import { Outlet, createFileRoute, useNavigate } from '@tanstack/react-router';
import { useEffect } from 'react';
import { useUserStore } from '~/stores/user-store';

export const Route = createFileRoute('/(protected)')({
  component: ProtectedLayout,
});

function ProtectedLayout() {
  const user = useUserStore((state) => state.user);
  const navigate = useNavigate();

  useEffect(() => {
    if (!user) navigate({ to: '/login' });
  }, [user, navigate]);

  return <Outlet />;
}
