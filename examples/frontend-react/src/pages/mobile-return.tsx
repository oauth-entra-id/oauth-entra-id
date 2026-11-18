import { useQueryClient } from '@tanstack/react-query';
import { useEffect } from 'react';
import { useNavigate } from 'react-router';
import { toast } from 'sonner';
import { Loading } from '~/components/pages/Loading';
import { getMobileTokens } from '~/lib/mobile-storage';
import { exchangeTicket } from '~/services/mobile-session';

export default function MobileReturn() {
  const navigate = useNavigate();
  const queryClient = useQueryClient();

  useEffect(() => {
    exchangeTicket()
      .catch(() => undefined)
      .then(async () => {
        const signedIn = getMobileTokens() !== null;
        if (!signedIn) toast.error('Could not complete the mobile login', { duration: 1000 });
        await queryClient.invalidateQueries({ queryKey: ['user'] });
        navigate(signedIn ? '/' : '/login', { replace: true });
      });
  }, [navigate, queryClient]);

  return <Loading />;
}
