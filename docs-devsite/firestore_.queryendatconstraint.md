Project: /docs/reference/js/_project.yaml
Book: /docs/reference/_book.yaml
page_type: reference

{% comment %}
DO NOT EDIT THIS FILE!
This is generated by the JS SDK team, and any local changes will be
overwritten. Changes should be made in the source code at
https://github.com/firebase/firebase-js-sdk
{% endcomment %}

# QueryEndAtConstraint class
A `QueryEndAtConstraint` is used to exclude documents from the end of a result set returned by a Firestore query. `QueryEndAtConstraint`<!-- -->s are created by invoking [endAt()](./firestore_.md#endat) or [endBefore()](./firestore_.md#endbefore) and can then be passed to [query()](./firestore_.md#query) to create a new query instance that also contains this `QueryEndAtConstraint`<!-- -->.

<b>Signature:</b>

```typescript
export declare class QueryEndAtConstraint extends QueryConstraint 
```
<b>Extends:</b> [QueryConstraint](./firestore_.queryconstraint.md#queryconstraint_class)

## Properties

|  Property | Modifiers | Type | Description |
|  --- | --- | --- | --- |
|  [type](./firestore_.queryendatconstraint.md#queryendatconstrainttype) |  | 'endBefore' \| 'endAt' | The type of this query constraint |

## QueryEndAtConstraint.type

The type of this query constraint

<b>Signature:</b>

```typescript
readonly type: 'endBefore' | 'endAt';
```