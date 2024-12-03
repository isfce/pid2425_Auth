delete from tuser;
MERGE INTO TUSER(USERNAME,EMAIL,PASSWORD,ROLE) VALUES
('admin','admin@isfce.be','$2a$10$BR98DmjHecYVdqtNz3UGcuyFop/ed0KfxOEAp1bdVXh8eF2iAfOz.','ROLE_ADMIN'),
('vo', 'vo@isfce.be','$2a$10$WvAj8iSJyIxDQWHysC4o6usLkzKW5bi9GThqYH2X/w/vVAm18nWcq','ROLE_CAFET'),
('val','val@isfce.be','$2a$10$ZZ4U5deuZBQqp/BNmKrG1e6OqiRwmaAfu.aaQfgBI9ehImH8AYZKC','ROLE_CAFET'),
('et1','et1@isfce.be','$2a$10$N8pzEKs1350SPT1vpomUo.zMEV1IR/LjXgOrBJ.QaeddZtKLVxR4q','ROLE_USER'),
('et2','et2@isfce.be','$2a$10$.Tlzs3a.2PEGK1gckhgaJuz4SWW2J1lWBf.4E3rOleziGDpExtp1W','ROLE_USER'),
('et3','et3@isfce.be','$2a$10$eeilUxVqPB8dXMsnzxiIp.OlOyD1isPtICWaRRL5VFofqcWcSURk2','ROLE_USER'),
('et4','et4@isfce.be','$2a$10$35yXfuSOyZkLLXFKXQbDLuzvdepJA2cFwxqu.VOsDuuAgf5ujVOuu','ROLE_USER');