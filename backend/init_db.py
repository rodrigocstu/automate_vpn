from app.db.session import engine, Base
from app.models.ansible import AnsibleJob, AuditLog, SecurityObject

def init_db():
    print("Iniciando creación de tablas en la base de datos...")
    Base.metadata.create_all(bind=engine)
    print("Tablas creadas con éxito.")

if __name__ == "__main__":
    init_db()
