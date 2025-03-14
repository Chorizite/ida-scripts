IDA (8.2) scripts for porting pdb ac client symbols / types to eor client

## Dependencies
- Ida 8.2+?
- [Diaphora](https://github.com/joxeankoret/diaphora)

## Working directory structure:
```
/
  pdbdata.sqlite # generated by `scripts/export-pdb-data.py` in ida
  /pdb
    acclient.exe # pdb client (you provide)
    acclient.pdb # pdb (you provide)
    types.idc # generated in ida
    acclient.exe.sqlite # generated from diaphora in ida
  /eor
    acclient.exe # eor client (you provide)
    acclient.exe.sqlite # generated from diaphora in ida
  /scripts  # these scripts
    export-pdb-data.py # run this in pdb client ida
    setup-new-eor-db.py # run this in eor client ida
```

## Instructions:

- Open ida pdb/acclient.exe (with pdb)
  - export types: `File -> Produce File -> Dump typeinfo to IDC file` to `/pdb/types.idc`
  - export a Diaphora database to `/pdb/acclient.exe.sqlite` with `Edit -> Plugins -> Diaphora`
  - close ida

- Open ida eor/acclient.exe (no pdb) and export a Diaphora database to eor/acclient.exe.sqlite
  - wait for initial database to build
  - export a Diaphora database to `/eor/acclient.exe.sqlite` with `Edit -> Plugins -> Diaphora`
  - close ida (save and pack database)

- run `diaphora.py -o /diff.sqlite /pdb/acclient.exe.sqlite /eor/acclient.exe.sqlite`

- Open ida pdb/acclient.exe (with pdb)
  - run `scripts/export-pdb-data.py` with `File -> Script file`
  - wait for it to finish (should be a few seconds)

- Open ida eor/acclient.exe (no pdb)
  - run `scripts/setup-new-eor-db.py` with `File -> Script file`
  - wait for it to finish (may be a few minutes)

- Enjoy ported symbols / types.