import { useNavigate } from '@tanstack/react-router';
import { useEffect } from 'react';

export function NotFound() {
  const navigate = useNavigate();

  useEffect(() => {
    navigate({ to: '/login' });
  }, [navigate]);

  return null;
}
