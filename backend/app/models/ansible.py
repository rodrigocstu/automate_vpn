from sqlalchemy import Column, Integer, String, JSON, DateTime, ForeignKey, Boolean, Text
from sqlalchemy.sql import func
from ..db.session import Base

class AnsibleJob(Base):
    __tablename__ = "ansible_jobs"

    id = Column(Integer, primary_key=True, index=True)
    task_id = Column(String, unique=True, index=True) # ID de Celery
    module_type = Column(String)
    status = Column(String) # queued, running, success, failed
    is_check_mode = Column(Boolean, default=False)
    payload = Column(JSON) # Lo que envió el usuario
    result_stats = Column(JSON, nullable=True) # Resumen de Ansible
    full_output = Column(Text, nullable=True) # Stdout completo
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    user_id = Column(Integer, nullable=True) # Para RBAC futuro

class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer)
    action = Column(String)
    module = Column(String)
    metadata_json = Column(JSON)
    timestamp = Column(DateTime(timezone=True), server_default=func.now())

class SecurityObject(Base):
    """Registro de objetos creados para evitar colisiones"""
    __tablename__ = "security_objects"
    
    id = Column(Integer, primary_key=True, index=True)
    object_type = Column(String) # address, service, group
    name = Column(String, unique=True, index=True)
    firewall_ip = Column(String)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
