from jcash.api.models import Address, Currency, LicenseAddress


def generate_query_check_address_licenses() -> str:
    query = """SELECT a.{addr_id}, c.{curr_id} as currency_id FROM currency AS c CROSS JOIN address AS a 
               LEFT JOIN (SELECT la.{la_id}, la.{la_addr_id}, la.{la_curr_id}, la.{la_is_remove_license} FROM 
                          license_address AS la WHERE la.{la_id} IN 
                          (SELECT MAX(cur_la.{la_id}) FROM license_address AS cur_la 
                          GROUP BY cur_la.{la_curr_id}, cur_la.{la_addr_id}) 
                          ) AS licenses ON licenses.{la_addr_id}=a.{addr_id} AND licenses.{la_curr_id}=c.{curr_id} 
               WHERE c.{curr_is_erc20_token} AND (a.{addr_is_removed}<>licenses.{la_is_remove_license} OR 
                                           licenses.{la_is_remove_license} IS NULL);""" \
    .format(addr_id=Address.id.field_name,
            addr_is_removed=Address.is_removed.field_name,
            curr_id=Currency.id.field_name,
            curr_is_erc20_token=Currency.is_erc20_token.field_name,
            la_id=LicenseAddress.id.field_name,
            la_addr_id=LicenseAddress.address.field.column,
            la_curr_id=LicenseAddress.currency.field.column,
            la_is_remove_license=LicenseAddress.is_remove_license.field_name)

    return query
