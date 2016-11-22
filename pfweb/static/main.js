function remove_rule(rule) {
	resp = confirm("Are you sure you wish to delete this rule?");

	if(resp == false) {
		return
	}

	location.href = "/firewall/rules/remove/" + rule
}

function remove_table(table) {
	/*resp = confirm("Are you sure you wish to delete this table?");

	if(resp == false) {
		return
	}*/

	$("#table_" + table).prop("checked", true);

	$("#delete_tables_submit").trigger("click");

	$("#table_" + table).prop("checked", false);

	//location.href = "/firewall/tables/remove/" + table
}

function add_address() {
	// Get next ID to use
	field_id = $('#address_fields').children().last().attr('id').split("-")[1];
	new_id = (parseInt(field_id) + 1);
	// Create new dom for addr
	field = $('<div class="col-sm-12 table-addresses" id="addr_container-' + new_id + '">' +
        '<label class="col-sm-2 control-label"></label>' +
        '<div class="col-sm-8">' +
            '<input type="text" class="form-control" id="addr' + new_id + '" name="addr' + new_id + '" value="" placeholder="Address" />' +
        '</div>' +
        '<div class="col-sm-2">' +
            '<button class="btn btn-danger btn-sm" type="button" value="Remove" name="removeaddr' + new_id + '" name="removeaddr' + new_id + '" onclick="table_remove_addr(' + new_id + ');">' +
                '<span class="glyphicon glyphicon-trash"></span>' +
                'Delete' +
            '</button>' +
        '</div>' +
    '</div>');
	// Add to the container
    $("#address_fields").append(field);
}

function table_remove_addr(id) {
	// Only clear the field if only one address
	if($('#address_fields').children().length == 1) {
		$("#addr_container-" + id + " input").val("");
		return
	}

	// Add Label to second field if removing the first address
	if(id == parseInt($('#address_fields').children().first().attr('id').split("-")[1])) {
		$('#address_fields').children().eq(1).children('label').text('Addresses');
	}
	// Remove addr div
	$("#addr_container-" + id).remove();
}

function toggle_fields() {
	// Modify protocol options based on address family
	if($('#af').val() == '*') {
		$('#icmp_option').hide();
		if($('#proto').val() == 'ICMP') {
			$('#proto').val('*');
		}

		$.each(['src', 'dst'], function(i, val) {
			console.log($('#' + val + '_addr_type').val());
			if($('#' + val + '_addr_type').val() == 'addrmask') {
				$('#' + val + '_addr_type').val('any');
				addr_type(val, 'any');
			}
			$('#form_' + val + '_addrmask_type').prop('disabled', true);
		});
	}
	else {
		$('#icmp_option').show();
		$('#form_src_addrmask_type').prop('disabled', false);
		$('#form_dst_addrmask_type').prop('disabled', false);
	}

	if($('#proto').val() != "ICMP" || $('#af').val() == '*') {
		// Hide ICMP Type form when protocol is ICMP or the AF is Any
		$('#form_icmptype').hide();

		// The ports must be hidden when ICMP is chosen even with AF is Any
		if($('#proto').val() == "ICMP") {
			$('#form_src_port').hide();
			$('#form_dst_port').hide();
		}
		else {
			// Only show ports when ICMP is not the chosen protocol
			$('#form_src_port').show();
			$('#form_dst_port').show();
		}

		return
	}

	// Make sure to hide ports when ICMP type is shown
	$('#form_src_port').hide();
	$('#form_dst_port').hide();
	
	// Show the correct ICMP options in the select for the AF chosen
	if($('#af').val() == 'IPv4') {
		$('#icmptype').show();
		$('#icmp6type').hide();
	}
	else if($('#af').val() == 'IPv6') {
		$('#icmp6type').show();
		$('#icmptype').hide();
	}
	
	// Show the whole ICMP type form
	$('#form_icmptype').show();
}

function addr_type(type, value) {
	if(value == 'addrmask') {
		$("#" + type + "_addr_table").hide();
		$("#form_" + type + "_addrmask").show();
	}
	else if(value == 'table') {
		$("#form_" + type + "_addrmask").hide();
		$("#" + type + "_addr_table").show();
	}
	if(value == 'any') {
		$("#" + type + "_addr_table").hide();
		$("#form_" + type + "_addrmask").hide();
	}
}

function load_edit_rules_page(){
	toggle_fields();
	addr_type('src', $('#src_addr_type').val());
	addr_type('dst', $('#dst_addr_type').val());
}