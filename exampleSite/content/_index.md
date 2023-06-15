---
title: "Hugo Encrypt Module Example"
date: 2013-06-12
draft: false
---

<!--more-->

## Encrypt With Default Password

```markdown
{{/*% encrypt %*/}}
**Hello World!**
{{/*% /encrypt %*/}}
```

Password: **{{< param "encrypt.password" >}}**.

{{% encrypt %}}
**Hello World!**
{{% /encrypt %}}

## Encrypt With Specified Password

```markdown
{{/*% encrypt "foo" %*/}}
**BAR**
{{/*% /encrypt %*/}}
```

Password: **foo**.

{{% encrypt "foo" %}}
**BAR**
{{% /encrypt %}}
