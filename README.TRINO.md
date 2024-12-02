## Rebuild Ranger Audit Plugins (add Opensearch Audit Store)

```bash
cd agents-audit && mvn clean package -DskipTests 
```

## Rebuild Ranger Plugins Common (fix Nashorn Exception)

```bash
cd agents-common && mvn clean package -DskipTests 
```