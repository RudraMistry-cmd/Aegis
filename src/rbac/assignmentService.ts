// Implements spec/rbac/assignments.md §1-§2, §5-§6, §8: the authorized assignment API and the
// privilege-escalation guards.
import {
  isValidId,
  type Id,
  type Principal,
  type RoleAssignment,
  type Subject,
  type Timestamp,
} from '../domain/index.js';
import { authError } from '../errors/index.js';
import type {
  AuditEvent,
  AuditSink,
  AssignmentStore,
  Clock,
  IdGenerator,
  UnitOfWork,
  UserStore,
} from '../ports/index.js';
import { CryptoIdGenerator } from '../ports/defaults.js';
import type { Authorizer } from '../policy/authorizer.js';
import type { Rbac } from './resolver.js';

/** The reserved system actor (assignments.md §1.1). */
export const SYSTEM_ACTOR: Id = 'system';

export interface EscalationGuardOptions {
  /** assignments.md §6.3. Default true. */
  readonly grantCeiling?: boolean;
  /** assignments.md §6.2. Default true. */
  readonly blockSelfAssign?: boolean;
  /** assignments.md §6.5. Default true. */
  readonly lastSuperuser?: boolean;
}

export interface AssignmentServiceOptions {
  readonly rbac: Rbac;
  readonly authorizer: Authorizer;
  readonly assignments: AssignmentStore;
  readonly users: UserStore;
  readonly uow: UnitOfWork;
  readonly clock: Clock;
  readonly audit?: AuditSink;
  readonly ids?: IdGenerator;
  readonly guards?: EscalationGuardOptions;
}

export interface AssignInput {
  readonly roleName: string;
  readonly expiresAt?: Timestamp | null;
  /**
   * Tenant of the target subject, when the deployment tracks tenants (assignments.md §6.6).
   * TODO(spec/rbac/assignments.md §3): Phase 1 has no tenant column on User, so the caller supplies
   * this value; it is used only to enforce the actor's own tenant boundary.
   */
  readonly targetTenantId?: Id;
}

/**
 * Role assignment with the escalation guards of assignments.md §6. Every check and the write run
 * inside one unit of work, so a concurrent change of the actor's own grants cannot be used to slip
 * an assignment through (INV-AUTHZ-07).
 */
export class AssignmentService {
  private readonly guards: Required<EscalationGuardOptions>;
  private readonly ids: IdGenerator;

  constructor(private readonly o: AssignmentServiceOptions) {
    this.guards = {
      grantCeiling: o.guards?.grantCeiling ?? true,
      blockSelfAssign: o.guards?.blockSelfAssign ?? true,
      lastSuperuser: o.guards?.lastSuperuser ?? true,
    };
    this.ids = o.ids ?? new CryptoIdGenerator();
  }

  /** Assigns a role. Idempotent (assignments.md §1.2). */
  async assign(
    actor: Principal | Subject,
    targetSubjectId: Id,
    input: AssignInput,
  ): Promise<'created' | 'unchanged' | 'updated'> {
    const now = this.o.clock.now();
    this.validateTarget(targetSubjectId);
    const role = this.o.rbac.catalog.role(input.roleName);
    if (!role)
      throw authError('VALIDATION_FAILED', {
        details: { field: 'roleName', rule: 'role.unknown' },
      });
    if (input.expiresAt !== undefined && input.expiresAt !== null && input.expiresAt <= now) {
      throw authError('VALIDATION_FAILED', {
        details: { field: 'expiresAt', rule: 'assignment.expired' },
      });
    }

    const systemActor = actor.id === SYSTEM_ACTOR;
    if (!systemActor) {
      // §6.1: the assignment API is itself authorized through the engine.
      await this.o.authorizer.assert(actor, 'assign', { type: 'role', id: input.roleName });
      // §6.2 / §6.4: no self-escalation.
      if (this.guards.blockSelfAssign && actor.id === targetSubjectId) {
        throw authError('ESCALATION_DENIED', { details: { rule: 'self_assign' } });
      }
      // §6.6: tenant boundary.
      if (
        actor.tenantId !== undefined &&
        input.targetTenantId !== undefined &&
        actor.tenantId !== input.targetTenantId
      ) {
        throw authError('ESCALATION_DENIED', { details: { rule: 'tenant_boundary' } });
      }
    }

    // spec/storage/interfaces.md §11.4: the unit contains storage work only. The audit event is
    // emitted after commit, so a rolled-back or retried transaction never produces one.
    const outcome = await this.o.uow.run(async (tx) => {
      if (!systemActor && this.guards.grantCeiling) {
        await this.assertGrantCeiling(actor, input.roleName, now);
      }
      if (!(await tx.users.getById(targetSubjectId))) throw authError('NOT_FOUND');
      if (!this.o.rbac.catalog.features.multiRole) {
        // §1.7: a second active assignment in the same scope is a conflict.
        const existing = await tx.assignments.listActive(targetSubjectId, now);
        if (existing.some((a) => a.roleName !== input.roleName)) {
          throw authError('CONFLICT', { details: { field: 'roleName' } });
        }
      }
      const record: RoleAssignment = {
        subjectId: targetSubjectId,
        roleName: input.roleName,
        scope: null,
        ...(input.expiresAt !== undefined ? { expiresAt: input.expiresAt } : {}),
        // §1.6 / §9 / INV-AUTHZ-08: grantedBy is derived, never taken from input.
        grantedBy: actor.id,
        grantedAt: now,
      };
      return tx.assignments.assign(record, now);
    });
    if (outcome !== 'unchanged') {
      await this.emit('role.assigned', now, actor, targetSubjectId, input.roleName, 'success');
    }
    return outcome;
  }

  /** Removes an assignment. Idempotent (assignments.md §1.3). */
  async unassign(
    actor: Principal | Subject,
    targetSubjectId: Id,
    roleName: string,
  ): Promise<boolean> {
    const now = this.o.clock.now();
    this.validateTarget(targetSubjectId);
    const systemActor = actor.id === SYSTEM_ACTOR;
    if (!systemActor) {
      await this.o.authorizer.assert(actor, 'revoke', { type: 'role', id: roleName });
    }
    // §11.4: audit emission happens after commit (see assign).
    const removed = await this.o.uow.run(async (tx) => {
      // §6.5: last-superuser protection, inside the unit so the count cannot change under us.
      if (this.guards.lastSuperuser && this.o.rbac.catalog.role(roleName)?.superuser === true) {
        const holders = await this.countSuperuserHolders(now);
        const target = await tx.assignments.listActive(targetSubjectId, now);
        const targetHolds = target.some(
          (a) => this.o.rbac.catalog.role(a.roleName)?.superuser === true,
        );
        if (targetHolds && holders <= 1) {
          throw authError('ESCALATION_DENIED', { details: { rule: 'last_superuser' } });
        }
      }
      return tx.assignments.unassign(targetSubjectId, roleName, null);
    });
    if (removed) {
      await this.emit('role.revoked', now, actor, targetSubjectId, roleName, 'success');
    }
    return removed;
  }

  /** Lists a subject's active assignments. Self-introspection needs no permission (§8.1). */
  async listFor(
    actor: Principal | Subject,
    targetSubjectId: Id,
  ): Promise<readonly RoleAssignment[]> {
    const now = this.o.clock.now();
    if (actor.id !== targetSubjectId && actor.id !== SYSTEM_ACTOR) {
      await this.o.authorizer.assert(actor, 'read', { type: 'role', id: targetSubjectId });
    }
    return this.o.assignments.listActive(targetSubjectId, now);
  }

  /**
   * §6.3 grant ceiling: the actor must already hold every registered permission the role confers.
   * A superuser role may be assigned only by a superuser holder.
   */
  private async assertGrantCeiling(
    actor: Principal | Subject,
    roleName: string,
    now: Timestamp,
  ): Promise<void> {
    const role = this.o.rbac.catalog.role(roleName);
    if (!role)
      throw authError('VALIDATION_FAILED', {
        details: { field: 'roleName', rule: 'role.unknown' },
      });
    const actorResolution = await this.o.rbac.resolve(actor, now);
    if (role.superuser) {
      const actorIsSuper = [...actorResolution.roles].some(
        (r) => this.o.rbac.catalog.role(r)?.superuser === true,
      );
      if (!actorIsSuper)
        throw authError('ESCALATION_DENIED', { details: { rule: 'grant_ceiling' } });
      return;
    }
    const rbac = this.o.rbac;
    const conferred = [...rbac.catalog.permissions].filter((p) => {
      for (const g of role.grants) if (matchesPattern(g, p)) return true;
      return false;
    });
    for (const p of conferred) {
      if (!rbac.allows(actorResolution, p)) {
        throw authError('ESCALATION_DENIED', { details: { rule: 'grant_ceiling' } });
      }
    }
  }

  /**
   * Counts active holders of any superuser role.
   *
   * DEVIATION: spec/storage/interfaces.md §8.2 declares a dedicated
   * `countActiveHoldersOfSuperuserRoles` port method. Phase 1 computes the same value from
   * `listSubjectsByRole`, keeping the store free of catalog knowledge. The guarantee is unchanged
   * because this runs inside the serialized unit of work (see docs/CONFORMANCE.md).
   */
  private async countSuperuserHolders(now: Timestamp): Promise<number> {
    const holders = new Set<Id>();
    for (const name of this.o.rbac.catalog.roleNames()) {
      if (this.o.rbac.catalog.role(name)?.superuser !== true) continue;
      let cursor: string | undefined;
      do {
        const page = await this.o.assignments.listSubjectsByRole(
          name,
          { limit: 100, ...(cursor !== undefined ? { cursor } : {}) },
          now,
        );
        for (const s of page.items) holders.add(s);
        cursor = page.nextCursor;
      } while (cursor !== undefined);
    }
    return holders.size;
  }

  private validateTarget(targetSubjectId: Id): void {
    if (!isValidId(targetSubjectId)) {
      throw authError('VALIDATION_FAILED', { details: { field: 'subjectId', rule: 'subject.id' } });
    }
  }

  /** §6.8: every successful change is audited with actor, target, role. */
  private async emit(
    type: 'role.assigned' | 'role.revoked',
    now: Timestamp,
    actor: Principal | Subject,
    targetSubjectId: Id,
    roleName: string,
    outcome: 'success' | 'denied',
  ): Promise<void> {
    if (!this.o.audit) return;
    const event: AuditEvent = {
      id: this.ids.newId(),
      type,
      at: now,
      severity: 'notice',
      actor: {
        id: actor.id,
        type: actor.type,
        ...('sessionId' in actor && typeof actor.sessionId === 'string'
          ? { sessionId: actor.sessionId }
          : {}),
      },
      target: { type: 'subject', id: targetSubjectId },
      outcome,
      context: {},
      details: { role: roleName, scope: null },
    };
    try {
      await this.o.audit.write(event);
    } catch {
      // assignments.md §6.8 / policy.md §7.3: an audit failure does not undo the change.
    }
  }
}

function matchesPattern(pattern: string, permission: string): boolean {
  const [pr, pa] = pattern.split(':') as [string, string];
  const [r, a] = permission.split(':') as [string, string];
  return (pr === '*' || pr === r) && (pa === '*' || pa === a);
}
