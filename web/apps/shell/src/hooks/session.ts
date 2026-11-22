import type { LoginChallenge, User } from "@hardy/api-client";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ApiFailure, api, unwrap } from "../api";
import { isChallenge } from "../auth/twoFactorRules";
import { useWM } from "../wm/store";

/** The signed-in user, or null when signed out. */
export function useMe(enabled = true) {
  return useQuery({
    enabled,
    queryKey: ["me"],
    queryFn: async (): Promise<User | null> => {
      try {
        return await unwrap(api.GET("/auth/me"));
      } catch (err) {
        if (err instanceof ApiFailure && err.status === 401) return null;
        throw err;
      }
    },
    staleTime: 60_000,
    retry: false,
  });
}

export function useSetupStatus(enabled = true) {
  return useQuery({ enabled, queryKey: ["setup"], queryFn: () => unwrap(api.GET("/setup")), staleTime: Infinity });
}

/** Signs in with a password: the user, or a challenge for a second step (two-factor sign-in). */
export function useLogin() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (body: { username: string; password: string }): Promise<User | LoginChallenge> =>
      (await unwrap(api.POST("/auth/login", { body }))) as User | LoginChallenge,
    onSuccess: (r) => {
      if (!isChallenge(r)) qc.setQueryData(["me"], r);
    },
  });
}

/** Finishes a sign-in with an authenticator or recovery code. */
export function useLoginCode() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: { challenge: string; code: string }) => unwrap(api.POST("/auth/login/2fa", { body })),
    onSuccess: (user) => qc.setQueryData(["me"], user),
  });
}

export function useCreateFirstAdmin() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: { username: string; password: string; displayName?: string }) =>
      unwrap(api.POST("/setup/admin", { body })),
    onSuccess: (user) => {
      qc.setQueryData(["setup"], { needsAdmin: false });
      qc.setQueryData(["me"], user);
    },
  });
}

export function useLogout() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: () => unwrap(api.POST("/auth/logout")),
    onSettled: () => {
      useWM.getState().closeAll();
      qc.clear();
      qc.setQueryData(["me"], null);
      qc.setQueryData(["setup"], { needsAdmin: false });
      // Fetch the rest (whether domain accounts can sign in) for the sign-in screen.
      void qc.invalidateQueries({ queryKey: ["setup"] });
    },
  });
}
