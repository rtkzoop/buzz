import type { AcpRuntimeCatalogEntry } from "@/shared/api/types";

function runtimeCommandIdentity(
  value: string | null | undefined,
): string | null {
  const trimmed = value?.trim();
  if (!trimmed) {
    return null;
  }

  const basename = trimmed.replaceAll("\\", "/").split("/").pop() ?? trimmed;
  return basename.toLowerCase().replace(/\.exe$/, "");
}

export function findRuntimeForCommand(
  runtimes: readonly AcpRuntimeCatalogEntry[],
  command: string | null | undefined,
): AcpRuntimeCatalogEntry | undefined {
  const exactCommand = command?.trim();
  const commandIdentity = runtimeCommandIdentity(command);
  if (!exactCommand || !commandIdentity) {
    return undefined;
  }

  return runtimes.find((runtime) => {
    const identities = runtime.id === "ompl" ? ["ompl", "omp"] : [];
    return (
      runtime.id === exactCommand ||
      runtime.command?.trim() === exactCommand ||
      runtime.binaryPath?.trim() === exactCommand ||
      runtimeCommandIdentity(runtime.command) === commandIdentity ||
      runtimeCommandIdentity(runtime.binaryPath) === commandIdentity ||
      identities.includes(commandIdentity)
    );
  });
}
