import pandas as pd
import json

def inspect_excel(filename):
    try:
        df = pd.read_excel(filename, nrows=5)
        print(f"Columnas found: {json.dumps(df.columns.tolist())}")
        print("\nPrimera fila de datos:")
        print(df.iloc[0].to_json(orient='index', indent=2))
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    inspect_excel('Anexo_5A_Base_establecimientos_(Final).xlsx')
