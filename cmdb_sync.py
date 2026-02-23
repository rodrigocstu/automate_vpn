import pandas as pd
import io
import uuid
import json
import sqlite3
import logging
from datetime import datetime

log = logging.getLogger("cmdb_sync")

class CMDBSyncService:
    def __init__(self, db_path):
        self.db_path = db_path

    def _get_db(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def process_national_registry(self, file_bytes, user_id, description="Carga Catastro Nacional"):
        """
        Procesa el archivo Excel en memoria y realiza la reconciliación.
        """
        batch_id = str(uuid.uuid4())
        file_stream = io.BytesIO(file_bytes)
        
        try:
            # Leer hojas principales
            # Usamos pd.read_excel que ya soporta openpyxl
            df_estab = pd.read_excel(file_stream, sheet_name='Estab')
            
            db = self._get_db()
            cursor = db.cursor()
            
            # Registrar el lote
            cursor.execute(
                "INSERT INTO cmdb_batches (id, user_id, description) VALUES (?, ?, ?)",
                (batch_id, user_id, description)
            )
            
            # Reconciliación de Establecimientos (Location_CI)
            results = self._reconcile_establishments(cursor, df_estab, batch_id)
            
            db.commit()
            return {
                "success": True,
                "batch_id": batch_id,
                "stats": results
            }
        except Exception as e:
            log.error(f"Error en sincronización CMDB: {str(e)}")
            return {"success": False, "error": str(e)}
        finally:
            if 'db' in locals():
                db.close()

    def _reconcile_establishments(self, cursor, df, batch_id):
        """
        Lógica de reconciliación para la hoja 'Estab'.
        Normaliza a Location_CI, Hardware_CI y Network_CI.
        """
        # 1. Preparar DataFrame
        df = df.copy()
        
        # Limpiar nombres de columnas (espacios en los extremos y convertir a string)
        df.columns = [str(c).strip() for c in df.columns]
        
        # Normalización de columnas críticas para evitar KeyError
        col_map_fixes = {
            "ESTABLECIMIENTO ": "ESTABLECIMIENTO",
            "ESTABLECIMIENTO": "ESTABLECIMIENTO",
            "DIRECCIÓN": "DIRECCIÓN",
            "DIRECCIÖN": "DIRECCIÓN",
            "DIRECCIN": "DIRECCIÓN"
        }
        
        # Renombrar dinámicamente si falta alguna
        for c in df.columns:
            uc = c.upper()
            if "ESTABLECIMIENTO" in uc and "ESTABLECIMIENTO" not in df.columns:
                df = df.rename(columns={c: "ESTABLECIMIENTO"})
            if "DIRECCI" in uc and "DIRECCIÓN" not in df.columns:
                df = df.rename(columns={c: "DIRECCIÓN"})
        
        # Asegurar tipos y limpieza de valores
        df['ESTABLECIMIENTO'] = df.get('ESTABLECIMIENTO', pd.Series(['']*len(df))).fillna('').astype(str).str.strip()
        df['DIRECCIÓN'] = df.get('DIRECCIÓN', pd.Series(['']*len(df))).fillna('').astype(str).str.strip()
        
        # Eliminar filas vacías
        df = df[df['ESTABLECIMIENTO'] != '']
        
        # Identificador único: ESTABLECIMIENTO + DIRECCIÓN
        df['natural_key'] = df['ESTABLECIMIENTO'].str.upper() + " || " + df['DIRECCIÓN'].str.upper()
        
        # ELIMINAR DUPLICADOS EN EL EXCEL (Mantener el primero)
        dupes_count = df.duplicated(subset=['natural_key']).sum()
        if dupes_count > 0:
            log.warning(f'"Found {dupes_count} duplicate rows in Excel, dropping them."')
            df = df.drop_duplicates(subset=['natural_key'], keep='first')
        
        stats = {"added": 0, "updated": 0, "deactivated": 0}
        
        # Obtener CIs actuales activos para detectar bajas
        cursor.execute("SELECT id, name, address FROM cmdb_location_ci WHERE is_active = 1")
        existing_cis = {f"{row['name']} || {row['address']}": row['id'] for row in cursor.fetchall()}
        
        processed_keys = set()
        
        for _, row in df.iterrows():
            key = row['natural_key']
            if not row['ESTABLECIMIENTO'] or not row['DIRECCIÓN']:
                continue
            
            processed_keys.add(key)
            
            # Datos de Ubicación (mapeo loc_data)
            loc_data = {
                "name": row['ESTABLECIMIENTO'],
                "address": row['DIRECCIÓN'],
                "region": row.get('REGION', ''),
                "comuna": row.get('COMUNA', ''),
                "provincia": row.get('PROVINCIA', row.get('PROVINCIA ', '')),
                "macrozone": row.get('MACROZONA', ''),
                "contratante": row.get('CONTRATANTE', ''),
                "tipo_establecimiento": row.get('tipo establecimiento', ''),
                "complejidad": row.get('Complejidad', ''),
                "casillas_correos": row.get('Casillas de Correos', ''),
                "batch_id": batch_id,
                "is_active": 1
            }
            
            # Datos de Hardware (mapeo hw_data)
            hw_data = {
                "model": row.get('Modelo Core Actual', ''),
                "machine_type": row.get('Match c/s ppal Machine Type', ''),
                "sw": row.get('SW', ''),
                "vc": row.get('VC', ''),
                "lineas_sobrevivencia": row.get('Lineas Sobrevivencia', ''),
                "telefonos_satelitales": row.get('TELÉFONOS SATELITALES', ''),
                "linea_800": row.get('LINEA 800', ''),
                "lineas_moviles": row.get('LINEAS MÓVILES', ''),
                "bam": row.get('BAM', ''),
                "samu_131": row.get('SAMU 131', ''),
                "ccm": row.get('CCM', ''),
                "fw": row.get('FW', ''),
                "fw_sugerido": row.get('FW Sugerido', ''),
                "batch_id": batch_id
            }
            
            # Datos de Red (mapeo net_data)
            net_data = {
                "access_type": row.get('ACCESO PPAL', ''),
                "bandwidth": row.get('BW DATOS PPAL', ''),
                "acceso_resp": row.get('ACCESO RESP', ''),
                "bw_datos_resp": row.get('BW DATOS RESP', ''),
                "acceso_resp2": row.get('ACCESO RESP2', ''),
                "bw_datos_resp2": row.get('BW DATOS RESP2', ''),
                "acceso_resp3": row.get('ACCESO RESP3', ''),
                "bw_datos_resp3": row.get('BW DATOS RESP3', ''),
                "wifi": row.get('WiFi', ''),
                "lineas_home": row.get('Líneas Home', ''),
                "internet_dedicado": row.get('INTERNET DEDICADO', ''),
                "enlace_1_sugerido": row.get('Enlace 1 sugerido', ''),
                "enlace_2_sugerido": row.get('ENLACE 2 sugerido', ''),
                "satelital_sugerido": row.get('Satelital sugerido', ''),
                "voz": row.get('VOZ', ''),
                "datos": row.get('DATOS', ''),
                "batch_id": batch_id
            }

            if key in existing_cis:
                loc_id = existing_cis[key]
                # Actualizamos ubicación
                cursor.execute("""
                    UPDATE cmdb_location_ci 
                    SET region=?, comuna=?, provincia=?, macrozone=?, contratante=?, 
                        tipo_establecimiento=?, complejidad=?, casillas_correos=?, batch_id=?, is_active=1
                    WHERE id=?
                """, (loc_data['region'], loc_data['comuna'], loc_data['provincia'], 
                      loc_data['macrozone'], loc_data['contratante'], loc_data['tipo_establecimiento'],
                      loc_data['complejidad'], loc_data['casillas_correos'], batch_id, loc_id))
                
                # Hardware y Network Upsert
                self._upsert_hardware(cursor, loc_id, hw_data, batch_id)
                self._upsert_network(cursor, loc_id, net_data, batch_id)
                
                stats["updated"] += 1
            else:
                # INSERT Nuevo
                cursor.execute("""
                    INSERT INTO cmdb_location_ci (name, address, region, comuna, provincia, 
                                               macrozone, contratante, tipo_establecimiento, 
                                               complejidad, casillas_correos, batch_id)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (loc_data['name'], loc_data['address'], loc_data['region'], 
                      loc_data['comuna'], loc_data['provincia'], loc_data['macrozone'],
                      loc_data['contratante'], loc_data['tipo_establecimiento'],
                      loc_data['complejidad'], loc_data['casillas_correos'], batch_id))
                loc_id = cursor.lastrowid
                
                self._upsert_hardware(cursor, loc_id, hw_data, batch_id)
                self._upsert_network(cursor, loc_id, net_data, batch_id)
                
                # Registrar en historial
                cursor.execute("""
                    INSERT INTO cmdb_history (ci_id, ci_type, batch_id, action, data_after)
                    VALUES (?, 'location', ?, 'INSERT', ?)
                """, (loc_id, batch_id, json.dumps(loc_data)))
                
                stats["added"] += 1
        
        # Bajas Lógicas (Records in DB but NOT in Excel)
        missing_keys = set(existing_cis.keys()) - processed_keys
        for mkey in missing_keys:
            mid = existing_cis[mkey]
            cursor.execute("UPDATE cmdb_location_ci SET is_active = 0, batch_id = ? WHERE id = ?", (batch_id, mid))
            cursor.execute("UPDATE cmdb_hardware_ci SET is_active = 0, batch_id = ? WHERE location_id = ?", (batch_id, mid))
            cursor.execute("UPDATE cmdb_network_ci SET is_active = 0, batch_id = ? WHERE location_id = ?", (batch_id, mid))
            
            # Registrar desactivación
            cursor.execute("""
                INSERT INTO cmdb_history (ci_id, ci_type, batch_id, action)
                VALUES (?, 'location', ?, 'DEACTIVATE')
            """, (mid, batch_id))
            
            stats["deactivated"] += 1
            
        return stats

    def _upsert_hardware(self, cursor, loc_id, data, batch_id):
        cursor.execute("SELECT id FROM cmdb_hardware_ci WHERE location_id = ?", (loc_id,))
        row = cursor.fetchone()
        if row:
            cursor.execute("""
                UPDATE cmdb_hardware_ci 
                SET model=?, machine_type=?, sw=?, vc=?, lineas_sobrevivencia=?, 
                    telefonos_satelitales=?, linea_800=?, lineas_moviles=?, bam=?, 
                    samu_131=?, ccm=?, fw=?, fw_sugerido=?, batch_id=?, is_active=1
                WHERE id=?
            """, (data['model'], data['machine_type'], data['sw'], data['vc'], data['lineas_sobrevivencia'],
                  data['telefonos_satelitales'], data['linea_800'], data['lineas_moviles'], data['bam'],
                  data['samu_131'], data['ccm'], data['fw'], data['fw_sugerido'], batch_id, row['id']))
        else:
            cursor.execute("""
                INSERT INTO cmdb_hardware_ci (location_id, model, machine_type, sw, vc, 
                                           lineas_sobrevivencia, telefonos_satelitales, 
                                           linea_800, lineas_moviles, bam, samu_131, 
                                           ccm, fw, fw_sugerido, batch_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (loc_id, data['model'], data['machine_type'], data['sw'], data['vc'],
                  data['lineas_sobrevivencia'], data['telefonos_satelitales'], data['linea_800'],
                  data['lineas_moviles'], data['bam'], data['samu_131'], data['ccm'], 
                  data['fw'], data['fw_sugerido'], batch_id))

    def _upsert_network(self, cursor, loc_id, data, batch_id):
        cursor.execute("SELECT id FROM cmdb_network_ci WHERE location_id = ?", (loc_id,))
        row = cursor.fetchone()
        if row:
            cursor.execute("""
                UPDATE cmdb_network_ci 
                SET access_type=?, bandwidth=?, acceso_resp=?, bw_datos_resp=?, 
                    acceso_resp2=?, bw_datos_resp2=?, acceso_resp3=?, bw_datos_resp3=?, 
                    wifi=?, lineas_home=?, internet_dedicado=?, enlace_1_sugerido=?, 
                    enlace_2_sugerido=?, satelital_sugerido=?, voz=?, datos=?, batch_id=?, is_active=1
                WHERE id=?
            """, (data['access_type'], data['bandwidth'], data['acceso_resp'], data['bw_datos_resp'],
                  data['acceso_resp2'], data['bw_datos_resp2'], data['acceso_resp3'], data['bw_datos_resp3'],
                  data['wifi'], data['lineas_home'], data['internet_dedicado'], data['enlace_1_sugerido'],
                  data['enlace_2_sugerido'], data['satelital_sugerido'], data['voz'], data['datos'],
                  batch_id, row['id']))
        else:
            cursor.execute("""
                INSERT INTO cmdb_network_ci (location_id, access_type, bandwidth, acceso_resp, 
                                          bw_datos_resp, acceso_resp2, bw_datos_resp2, 
                                          acceso_resp3, bw_datos_resp3, wifi, lineas_home, 
                                          internet_dedicado, enlace_1_sugerido, 
                                          enlace_2_sugerido, satelital_sugerido, voz, datos, batch_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (loc_id, data['access_type'], data['bandwidth'], data['acceso_resp'],
                  data['bw_datos_resp'], data['acceso_resp2'], data['bw_datos_resp2'],
                  data['acceso_resp3'], data['bw_datos_resp3'], data['wifi'], data['lineas_home'],
                  data['internet_dedicado'], data['enlace_1_sugerido'], data['enlace_2_sugerido'],
                  data['satelital_sugerido'], data['voz'], data['datos'], batch_id))

    def undo_batch(self, batch_id):
        """
        Revierte todas las operaciones de un batch_id.
        Implementa lógica compleja de restauración.
        """
        db = self._get_db()
        cursor = db.cursor()
        
        try:
            # 1. Encontrar lo que se insertó en este lote y borrarlo
            cursor.execute("DELETE FROM cmdb_location_ci WHERE batch_id = ? AND id IN (SELECT ci_id FROM cmdb_history WHERE batch_id=? AND action='INSERT')", (batch_id, batch_id))
            cursor.execute("DELETE FROM cmdb_hardware_ci WHERE batch_id = ?", (batch_id,))
            cursor.execute("DELETE FROM cmdb_network_ci WHERE batch_id = ?", (batch_id,))
            
            # 2. Encontrar lo que se desactivó y reactivarlo
            cursor.execute("UPDATE cmdb_location_ci SET is_active = 1 WHERE batch_id = ?", (batch_id,))
            cursor.execute("UPDATE cmdb_hardware_ci SET is_active = 1 WHERE batch_id = ?", (batch_id,))
            cursor.execute("UPDATE cmdb_network_ci SET is_active = 1 WHERE batch_id = ?", (batch_id,))
            
            # Marcar lote como deshecho
            cursor.execute("UPDATE cmdb_batches SET status = 'undone' WHERE id = ?", (batch_id,))
            
            db.commit()
            return {"success": True}
        except Exception as e:
            return {"success": False, "error": str(e)}
        finally:
            db.close()
