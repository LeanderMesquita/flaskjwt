from marshmallow import Schema, fields

class UserSchema(Schema):
    id = fields.Integer(dump_only=True)
    username = fields.String(dump_only=True)
    email = fields.String(dump_only=True)
    password = fields.String(dump_only=True)
    cpf_cnpj = fields.String(dump_only=True)
