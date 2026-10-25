import { PageHeader } from "../../ui";
import { AuditLog } from "../shared";

export default function LogCenter() {
  return (
    <div className="app-layout__content">
      <PageHeader title="Log Center" subtitle="Who did what, and when. System service logs arrive in a later build." />
      <AuditLog />
    </div>
  );
}
