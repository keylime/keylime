--
-- PostgreSQL database dump
--

-- Dumped from database version 12.4
-- Dumped by pg_dump version 12.4

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: verifiermain; Type: TABLE; Schema: public; Owner: keylime
--

CREATE TABLE public.verifiermain (
    agent_id character varying(80) NOT NULL,
    v character varying,
    ip character varying(15),
    port integer,
    operational_state integer,
    public_key character varying,
    tpm_policy character varying,
    vtpm_policy character varying,
    meta_data character varying,
    allowlist character varying,
    ima_sign_verification_keys character varying,
    revocation_key character varying,
    accept_tpm_hash_algs text,
    accept_tpm_encryption_algs text,
    accept_tpm_signing_algs text,
    hash_alg character varying,
    enc_alg character varying,
    sign_alg character varying,
    boottime integer,
    ima_pcrs character varying,
    pcr10 bytea,
    next_ima_ml_entry integer,
    learned_keyrings character varying,
);


ALTER TABLE public.verifiermain OWNER TO keylime;

--
-- Name: verifiermain verifiermain_pkey; Type: CONSTRAINT; Schema: public; Owner: keylime
--

ALTER TABLE ONLY public.verifiermain
    ADD CONSTRAINT verifiermain_pkey PRIMARY KEY (agent_id);

--
-- PostgreSQL database dump complete
--

