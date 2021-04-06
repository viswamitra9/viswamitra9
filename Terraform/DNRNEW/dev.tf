module "networking" {
source = "./modules/networking"
}
module "kms" {
source = "./modules/kms"
}
module "s3" {
source = "./modules/s3"
kms_master_key_id = module.kms.arn
depends_on=[module.kms,module.networking]
}
module "rds" {
source = "./modules/rds"
kms_key_id = module.kms.arn
subnet_group_name = module.networking.db_subnet_name
security_group_id = [module.networking.aws_security_group_id]
depends_on=[module.kms,module.networking]
}
module "pentaho" {
  source = "./modules/pentaho"
  security_group_id = [module.networking.aws_security_group_id]
  subnet_id = module.networking.subnet_id
  depends_on=[module.kms,module.networking]
}