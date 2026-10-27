import type { VMDevice } from "@hardy/api-client";
import { InfoIcon } from "../../icons";
import { DevicePicker } from "./devices";

/** The New VM wizard's devices step: part D's picker with a few words. */
export function DevicesStep({ vm, gpu, devices, onChange }: { vm: string; gpu: boolean; devices: VMDevice[]; onChange: (d: VMDevice[]) => void }) {
  return (
    <>
      <h2 className="wiz__title">Devices</h2>
      <p className="wiz__lead">
        Give the VM a whole graphics card, a USB stick or another device. {gpu ? "A gaming VM wants its own graphics card." : "Most VMs don't need any."}
      </p>
      <DevicePicker vm={vm} value={devices} onChange={onChange} />
      <div className="tip">
        <InfoIcon size={16} />
        <span>A graphics card given to a VM goes back to Docker apps whenever the VM is off.</span>
      </div>
    </>
  );
}
