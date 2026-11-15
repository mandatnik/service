// Recipients are the union of explicitly selected machines and the eligible
// members of selected groups. The backend performs the authoritative merge;
// this helper keeps the UI counter and duplicate warnings honest.
export function selectedRecipientIDs(machineIDs, groupIDs, groups, selectableMachineIDs) {
  const selectable = selectableMachineIDs instanceof Set ? selectableMachineIDs : new Set(selectableMachineIDs || [])
  const groupByID = new Map((groups || []).map(group => [group.id, group]))
  const recipients = new Set()
  for (const id of machineIDs || []) {
    if (selectable.has(id)) recipients.add(id)
  }
  for (const groupID of groupIDs || []) {
    const group = groupByID.get(groupID)
    for (const id of group?.machine_ids || []) {
      if (selectable.has(id)) recipients.add(id)
    }
  }
  return [...recipients]
}

export function selectableMachineIDs(machines) {
  return new Set((machines || [])
    .filter(machine => !machine.archived && machine.active_registration !== false)
    .map(machine => machine.id))
}
